//go:build search

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
	"zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestRawVulnerabilitiesEndpointReturnsNativeReport(t *testing.T) {
	digest := godigest.FromString("raw-report-manifest")
	var scannerImages []string
	controller, _ := newRawVulnerabilityTestController(t, nil, mocks.CveScannerMock{
		ScanRawReportFn: func(_ context.Context, image string) (cvemodel.RawScanResult, error) {
			scannerImages = append(scannerImages, image)

			reportJSON, err := json.Marshal(trivyTypes.Report{
				SchemaVersion: 2,
				ArtifactName:  "team/app:v1",
				Results: []trivyTypes.Result{{
					Target: "app (alpine 3.20)",
					Class:  "os-pkgs",
					Type:   "alpine",
				}},
			})

			return cvemodel.RawScanResult{ReportJSON: reportJSON}, err
		},
	})

	var responseBodies [][]byte
	for _, ref := range []string{"v1", digest.String()} {
		request := httptest.NewRequest(http.MethodGet,
			"/v2/team/app/vulnerabilities?ref="+ref, http.NoBody)
		response := httptest.NewRecorder()
		controller.Router.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, "application/json", response.Header().Get("Content-Type"))
		var report trivyTypes.Report
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &report))
		assert.Equal(t, 2, report.SchemaVersion)
		assert.Equal(t, "app (alpine 3.20)", report.Results[0].Target)
		assert.Equal(t, trivyTypes.ResultClass("os-pkgs"), report.Results[0].Class)
		responseBodies = append(responseBodies, response.Body.Bytes())
	}

	// the reference is forwarded verbatim; resolving it is the scanner's job, as for the CVE APIs
	assert.Equal(t, []string{"team/app:v1", "team/app@" + digest.String()}, scannerImages)
	assert.Equal(t, responseBodies[0], responseBodies[1])
}

func TestRawVulnerabilitiesEndpointRejectsInvalidReferences(t *testing.T) {
	scanCalls := 0
	controller, _ := newRawVulnerabilityTestController(t, nil, mocks.CveScannerMock{
		ScanRawReportFn: func(context.Context, string) (cvemodel.RawScanResult, error) {
			scanCalls++

			return cvemodel.RawScanResult{ReportJSON: []byte("{}")}, nil
		},
	})

	for _, target := range []string{
		"/v2/team/app/vulnerabilities",
		"/v2/team/app/vulnerabilities?ref=",
		"/v2/team/app/vulnerabilities?ref=bad%3Adigest",
		"/v2/team/app/vulnerabilities?ref=v1&ref=v2",
	} {
		request := httptest.NewRequest(http.MethodGet, target, http.NoBody)
		response := httptest.NewRecorder()
		controller.Router.ServeHTTP(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code, target)
	}

	assert.Zero(t, scanCalls)
}

func TestRawVulnerabilitiesEndpointMapsScannerErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		status       int
		code         string
		bodyPhrase   string
		absentPhrase string
	}{
		{
			name:   "unknown manifest",
			err:    zerr.ErrManifestNotFound,
			status: http.StatusNotFound,
			code:   apiErr.MANIFEST_UNKNOWN.String(),
		},
		{
			name:   "unknown repository",
			err:    zerr.ErrRepoMetaNotFound,
			status: http.StatusNotFound,
			code:   apiErr.NAME_UNKNOWN.String(),
		},
		{
			name:   "cve search disabled",
			err:    zerr.ErrCVESearchDisabled,
			status: http.StatusNotImplemented,
			code:   apiErr.UNSUPPORTED.String(),
		},
		{
			name:       "index requires a platform manifest",
			err:        fmt.Errorf("%w: use a platform-specific manifest digest", zerr.ErrScanNotSupported),
			status:     http.StatusUnsupportedMediaType,
			code:       apiErr.UNSUPPORTED.String(),
			bodyPhrase: "platform-specific manifest digest",
		},
		{
			name:   "trivy failure",
			err:    errors.New("trivy scan failed"),
			status: http.StatusInternalServerError,
			code:   apiErr.MANIFEST_INVALID.String(),
			// internal error text may carry storage paths, so it must not reach the client
			absentPhrase: "trivy scan failed",
		},
		{
			name:   "trivy database missing",
			err:    zerr.ErrCVEDBNotFound,
			status: http.StatusInternalServerError,
			code:   apiErr.MANIFEST_INVALID.String(),
		},
		{
			// an abandoned scan must not look like an empty report
			name:   "client canceled the request",
			err:    context.Canceled,
			status: http.StatusInternalServerError,
			code:   apiErr.MANIFEST_INVALID.String(),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			controller, _ := newRawVulnerabilityTestController(t, nil, mocks.CveScannerMock{
				ScanRawReportFn: func(context.Context, string) (cvemodel.RawScanResult, error) {
					return cvemodel.RawScanResult{}, testCase.err
				},
			})

			request := httptest.NewRequest(http.MethodGet, "/v2/team/app/vulnerabilities?ref=v1", http.NoBody)
			response := httptest.NewRecorder()
			controller.Router.ServeHTTP(response, request)

			assert.Equal(t, testCase.status, response.Code)
			if testCase.code != "" {
				var responseErrors apiErr.ErrorList
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &responseErrors))
				require.Len(t, responseErrors.Errors, 1)
				assert.Equal(t, testCase.code, responseErrors.Errors[0].Code)
			}
			if testCase.bodyPhrase != "" {
				assert.Contains(t, response.Body.String(), testCase.bodyPhrase)
			}
			if testCase.absentPhrase != "" {
				assert.NotContains(t, response.Body.String(), testCase.absentPhrase)
			}
		})
	}
}

func TestRawVulnerabilitiesEndpointAuthorizesQueryReference(t *testing.T) {
	accessControl := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"team/app": {Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.reference == "allowed-tag"`,
					Message:    "reference not allowed",
				}},
			}}},
		},
	}
	scanCalls := 0
	controller, routeHandler := newRawVulnerabilityTestController(t, accessControl, mocks.CveScannerMock{
		ScanRawReportFn: func(context.Context, string) (cvemodel.RawScanResult, error) {
			scanCalls++

			return cvemodel.RawScanResult{ReportJSON: []byte("{}")}, nil
		},
	})

	request := httptest.NewRequest(http.MethodGet, "/v2/team/app/vulnerabilities?ref=denied-tag", http.NoBody)
	userAccess := requestcontext.NewUserAccessControl()
	userAccess.SetUsername("alice")

	handler := newRawVulnerabilityAuthzRouter(controller, routeHandler, userAccess)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.Zero(t, scanCalls)

	request = httptest.NewRequest(http.MethodGet, "/v2/team/app/vulnerabilities", http.NoBody)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusBadRequest, response.Code)
	assert.Zero(t, scanCalls)

	request = httptest.NewRequest(http.MethodGet, "/v2/team/app/vulnerabilities?ref=allowed-tag", http.NoBody)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, 1, scanCalls)
}

// A tag named "vulnerabilities" must not be mistaken for the raw report endpoint, otherwise the
// manifest routes would skip authorization entirely.
func TestManifestTaggedVulnerabilitiesStillAuthorized(t *testing.T) {
	accessControl := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"team/app": {Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.reference == "allowed-tag"`,
					Message:    "reference not allowed",
				}},
			}}},
		},
	}
	scanCalls := 0
	controller, routeHandler := newRawVulnerabilityTestController(t, accessControl, mocks.CveScannerMock{
		ScanRawReportFn: func(context.Context, string) (cvemodel.RawScanResult, error) {
			scanCalls++

			return cvemodel.RawScanResult{ReportJSON: []byte("{}")}, nil
		},
	})

	userAccess := requestcontext.NewUserAccessControl()
	userAccess.SetUsername("alice")
	handler := newRawVulnerabilityAuthzRouter(controller, routeHandler, userAccess)

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		request := httptest.NewRequest(method, "/v2/team/app/manifests/vulnerabilities", http.NoBody)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		assert.Equal(t, http.StatusForbidden, response.Code,
			"%s of a tag named vulnerabilities must be authorized", method)
	}

	assert.Zero(t, scanCalls)
}

// The authz middleware deliberately lets OPTIONS through unauthorized, so registering OPTIONS on
// this route would serve the report to any anonymous caller and run a scan on their behalf.
func TestRawVulnerabilitiesEndpointRejectsPreflight(t *testing.T) {
	accessControl := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"team/app": {Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
			}}},
		},
	}

	scanCalls := 0
	controller, _ := newRawVulnerabilityTestController(t, accessControl, mocks.CveScannerMock{
		ScanRawReportFn: func(context.Context, string) (cvemodel.RawScanResult, error) {
			scanCalls++

			return cvemodel.RawScanResult{ReportJSON: []byte(`{"SchemaVersion":2}`)}, nil
		},
	})

	request := httptest.NewRequest(http.MethodOptions, "/v2/team/app/vulnerabilities?ref=v1", http.NoBody)
	request.Header.Set("Origin", "https://ui.example.test")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)

	response := httptest.NewRecorder()
	controller.Router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)
	assert.Zero(t, response.Body.Len())
	assert.Zero(t, scanCalls)
}

// newRawVulnerabilityAuthzRouter wires the real routes so route matching, the authz middleware and
// the handlers are exercised together, with authn replaced by a fixed identity.
func newRawVulnerabilityAuthzRouter(controller *api.Controller, routeHandler *api.RouteHandler,
	userAccess *requestcontext.UserAccessControl,
) http.Handler {
	router := mux.NewRouter()
	distSpec := router.PathPrefix(constants.RoutePrefix).Subrouter()
	distSpec.Use(api.BaseAuthzHandler(controller), api.DistSpecAuthzHandler(controller))

	distSpec.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
		routeHandler.GetManifest).Methods(http.MethodGet)
	distSpec.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
		routeHandler.DeleteManifest).Methods(http.MethodDelete)
	distSpec.HandleFunc(fmt.Sprintf("/{name:%s}/vulnerabilities", zreg.NameRegexp.String()),
		routeHandler.GetRawVulnerabilities).
		Methods(http.MethodGet).Name(constants.RawVulnerabilitiesRouteName)

	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		userAccess.SaveOnRequest(request)
		request = request.WithContext(context.WithValue(request.Context(),
			requestcontext.GetAuthnMiddlewareCtxKey(),
			requestcontext.AuthnMiddlewareContext{AuthnType: api.BASIC}))
		router.ServeHTTP(response, request)
	})
}

func newRawVulnerabilityTestController(t *testing.T, accessControl *config.AccessControlConfig,
	scanner mocks.CveScannerMock,
) (*api.Controller, *api.RouteHandler) {
	t.Helper()
	appConfig := config.New()
	appConfig.HTTP.AccessControl = accessControl
	controller := api.NewController(appConfig)
	controller.Router = mux.NewRouter()
	controller.CveScanner = scanner
	routeHandler := api.NewRouteHandler(controller)

	return controller, routeHandler
}
