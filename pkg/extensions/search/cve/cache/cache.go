package cache

import (
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

type CveCache struct {
	cache *lru.Cache[string, map[string]zcommon.CVE]
	log   log.Logger
}

func NewCveCache(size int, log log.Logger) *CveCache {
	cache, _ := lru.New[string, map[string]zcommon.CVE](size)

	return &CveCache{cache: cache, log: log}
}

func (cveCache *CveCache) Add(image string, cveMap map[string]zcommon.CVE) {
	cveCache.cache.Add(image, cveMap)
}

func (cveCache *CveCache) Contains(image string) bool {
	return cveCache.cache.Contains(image)
}

func (cveCache *CveCache) Get(image string) map[string]zcommon.CVE {
	cveMap, ok := cveCache.cache.Get(image)
	if !ok {
		return nil
	}

	return cveMap
}

func (cveCache *CveCache) Purge() {
	cveCache.cache.Purge()
}

// rawReportCacheMaxEntries is a backstop on entry count; the byte budget is the real bound.
const rawReportCacheMaxEntries = 100000

// RawReportCache stores serialized Trivy reports under a total byte budget. A count-based limit
// would not bound memory here, since a single report ranges from kilobytes to tens of megabytes.
// Entries are keyed by repo and digest rather than by digest alone, because a report records the
// repository it was scanned through.
type RawReportCache struct {
	mutex     sync.Mutex
	cache     *lru.Cache[string, []byte]
	maxBytes  int64
	usedBytes int64
}

// NewRawReportCache budgets the cache to maxBytes. A non-positive budget disables caching.
func NewRawReportCache(maxBytes int64) *RawReportCache {
	cache, _ := lru.New[string, []byte](rawReportCacheMaxEntries)

	return &RawReportCache{cache: cache, maxBytes: maxBytes}
}

// Add stores report unless it alone exceeds the budget, evicting least-recently-used entries
// until the total fits.
func (reportCache *RawReportCache) Add(key string, report []byte) {
	size := int64(len(report))

	reportCache.mutex.Lock()
	defer reportCache.mutex.Unlock()

	if size > reportCache.maxBytes {
		return
	}

	// replacing a key does not evict, so discount the previous value explicitly
	if previous, ok := reportCache.cache.Peek(key); ok {
		reportCache.usedBytes -= int64(len(previous))
	}

	reportCache.cache.Add(key, report)
	reportCache.usedBytes += size

	for reportCache.usedBytes > reportCache.maxBytes {
		_, evicted, ok := reportCache.cache.RemoveOldest()
		if !ok {
			break
		}

		reportCache.usedBytes -= int64(len(evicted))
	}
}

func (reportCache *RawReportCache) Get(key string) ([]byte, bool) {
	reportCache.mutex.Lock()
	defer reportCache.mutex.Unlock()

	return reportCache.cache.Get(key)
}

func (reportCache *RawReportCache) Purge() {
	reportCache.mutex.Lock()
	defer reportCache.mutex.Unlock()

	reportCache.cache.Purge()
	reportCache.usedBytes = 0
}

// UsedBytes reports the total size of the cached reports.
func (reportCache *RawReportCache) UsedBytes() int64 {
	reportCache.mutex.Lock()
	defer reportCache.mutex.Unlock()

	return reportCache.usedBytes
}
