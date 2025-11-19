package detector

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/javicosvml/rankle-go/pkg/models"
)

// Detector handles technology detection
type Detector struct{}

// New creates a new Detector instance
func New() *Detector {
	return &Detector{}
}

// DetectTechnologies analyzes HTML content and headers to detect technologies
func (d *Detector) DetectTechnologies(body string, headers map[string]string) *models.Technologies {
	tech := &models.Technologies{
		Frameworks:  []string{},
		Libraries:   []string{},
		Languages:   []string{},
		Analytics:   []string{},
		WebServers:  []string{},
		Fingerprint: []string{},
	}

	bodyLower := strings.ToLower(body)

	// Detect CMS
	tech.CMS = d.detectCMS(bodyLower, headers)

	// Detect JavaScript libraries
	tech.Libraries = d.detectLibraries(bodyLower)

	// Detect frameworks
	tech.Frameworks = d.detectFrameworks(bodyLower, headers)

	// Detect web server from headers
	if server, ok := headers["server"]; ok {
		tech.WebServers = append(tech.WebServers, server)
	}

	// Detect programming languages
	tech.Languages = d.detectLanguages(bodyLower, headers)

	// Detect analytics
	tech.Analytics = d.detectAnalytics(bodyLower)

	return tech
}

// detectCMS identifies Content Management Systems
func (d *Detector) detectCMS(body string, headers map[string]string) string {
	indicators := make(map[string]int)

	// WordPress
	wpPatterns := []string{
		"wp-content",
		"wp-includes",
		"wordpress",
		"/wp-json/",
		"wp-emoji",
	}
	for _, pattern := range wpPatterns {
		if strings.Contains(body, pattern) {
			indicators["WordPress"]++
		}
	}

	// Drupal
	drupalPatterns := []string{
		"drupal",
		"/sites/default/files",
		"drupal.js",
		"drupal-settings-json",
		"/core/misc/drupal",
	}
	for _, pattern := range drupalPatterns {
		if strings.Contains(body, pattern) {
			indicators["Drupal"]++
		}
	}

	// Joomla
	joomlaPatterns := []string{
		"joomla",
		"/components/com_",
		"/modules/mod_",
		"option=com_",
	}
	for _, pattern := range joomlaPatterns {
		if strings.Contains(body, pattern) {
			indicators["Joomla"]++
		}
	}

	// Magento
	magentoPatterns := []string{
		"magento",
		"mage/cookies.js",
		"/skin/frontend",
	}
	for _, pattern := range magentoPatterns {
		if strings.Contains(body, pattern) {
			indicators["Magento"]++
		}
	}

	// Shopify
	if strings.Contains(body, "shopify") || strings.Contains(body, "cdn.shopify.com") {
		indicators["Shopify"] += 2
	}

	// Check headers for CMS clues
	if xGenerator, ok := headers["x-generator"]; ok {
		if strings.Contains(strings.ToLower(xGenerator), "drupal") {
			indicators["Drupal"] += 2
		}
	}

	// Return CMS with highest score
	maxScore := 0
	detectedCMS := ""
	for cms, score := range indicators {
		if score >= 2 && score > maxScore {
			maxScore = score
			detectedCMS = cms
		}
	}

	return detectedCMS
}

// detectLibraries identifies JavaScript libraries
func (d *Detector) detectLibraries(body string) []string {
	libraries := []string{}

	libPatterns := map[string][]string{
		"jQuery":    {"jquery", "jquery.min.js", "jquery.js"},
		"React":     {"react", "react.min.js", "react-dom"},
		"Vue.js":    {"vue.js", "vue.min.js", "vue.runtime"},
		"Angular":   {"angular.js", "angular.min.js", "ng-"},
		"Bootstrap": {"bootstrap.css", "bootstrap.min.css", "bootstrap.js"},
		"D3.js":     {"d3.js", "d3.min.js", "d3.v"},
		"Lodash":    {"lodash", "lodash.min.js"},
		"Moment.js": {"moment.js", "moment.min.js"},
	}

	for lib, patterns := range libPatterns {
		for _, pattern := range patterns {
			if strings.Contains(body, pattern) {
				libraries = append(libraries, lib)
				break
			}
		}
	}

	return libraries
}

// detectFrameworks identifies web frameworks
func (d *Detector) detectFrameworks(body string, headers map[string]string) []string {
	frameworks := []string{}

	// Next.js
	if strings.Contains(body, "__next") || strings.Contains(body, "_next/static") {
		frameworks = append(frameworks, "Next.js")
	}

	// Nuxt.js
	if strings.Contains(body, "__nuxt") || strings.Contains(body, "_nuxt/") {
		frameworks = append(frameworks, "Nuxt.js")
	}

	// Laravel (from headers)
	if xFramework, ok := headers["x-powered-by"]; ok {
		if strings.Contains(strings.ToLower(xFramework), "laravel") {
			frameworks = append(frameworks, "Laravel")
		}
	}

	return frameworks
}

// detectLanguages identifies programming languages
func (d *Detector) detectLanguages(body string, headers map[string]string) []string {
	languages := []string{}

	if xPoweredBy, ok := headers["x-powered-by"]; ok {
		xPoweredBy = strings.ToLower(xPoweredBy)
		if strings.Contains(xPoweredBy, "php") {
			languages = append(languages, "PHP")
		}
		if strings.Contains(xPoweredBy, "asp.net") {
			languages = append(languages, "ASP.NET")
		}
	}

	// Check for .php extensions in body
	if matched, _ := regexp.MatchString(`\.php(\?|"|'| |$)`, body); matched {
		if !contains(languages, "PHP") {
			languages = append(languages, "PHP")
		}
	}

	return languages
}

// detectAnalytics identifies analytics services
func (d *Detector) detectAnalytics(body string) []string {
	analytics := []string{}

	analyticsPatterns := map[string]string{
		"Google Analytics":   "google-analytics.com",
		"Google Tag Manager": "googletagmanager.com",
		"Facebook Pixel":     "facebook.net/en_us/fbevents.js",
		"Hotjar":             "hotjar.com",
		"Mixpanel":           "mixpanel.com",
	}

	for service, pattern := range analyticsPatterns {
		if strings.Contains(body, pattern) {
			analytics = append(analytics, service)
		}
	}

	return analytics
}

// DetectCDN identifies CDN providers from headers and CNAME records
func (d *Detector) DetectCDN(headers map[string]string, cnames []string) string {
	cdnPatterns := map[string][]string{
		"Cloudflare":        {"cloudflare", "cf-ray"},
		"Akamai":            {"akamai", "akamaihd.net"},
		"Fastly":            {"fastly", "x-fastly-request-id"},
		"Amazon CloudFront": {"cloudfront.net", "x-amz-cf-id"},
		"Azure CDN":         {"azureedge.net"},
		"Google Cloud CDN":  {"googlevideo.com", "googleusercontent.com"},
		"TransparentEdge":   {"transparentcdn.com", "transparentedge"},
		"MaxCDN":            {"maxcdn.com"},
		"KeyCDN":            {"keycdn.com"},
		"Sucuri":            {"sucuri"},
	}

	// Check headers
	for cdn, patterns := range cdnPatterns {
		for headerKey, headerValue := range headers {
			headerValue = strings.ToLower(headerValue)
			headerKey = strings.ToLower(headerKey)
			for _, pattern := range patterns {
				if strings.Contains(headerValue, strings.ToLower(pattern)) ||
					strings.Contains(headerKey, strings.ToLower(pattern)) {
					return cdn
				}
			}
		}
	}

	// Check CNAMEs
	for _, cname := range cnames {
		cnameLower := strings.ToLower(cname)
		for cdn, patterns := range cdnPatterns {
			for _, pattern := range patterns {
				if strings.Contains(cnameLower, strings.ToLower(pattern)) {
					return cdn
				}
			}
		}
	}

	return ""
}

// DetectWAF identifies Web Application Firewalls
func (d *Detector) DetectWAF(headers map[string]string, resp *http.Response) string {
	wafPatterns := map[string][]string{
		"Cloudflare":      {"cf-ray", "cloudflare"},
		"Imperva":         {"x-iinfo", "incap"},
		"Sucuri":          {"x-sucuri", "sucuri"},
		"ModSecurity":     {"mod_security", "modsecurity"},
		"F5 BIG-IP":       {"bigip", "f5"},
		"Barracuda":       {"barracuda"},
		"Akamai":          {"akamai"},
		"AWS WAF":         {"awswaf", "x-amzn"},
		"TransparentEdge": {"transparentedge", "tedge"},
	}

	for waf, patterns := range wafPatterns {
		for headerKey, headerValue := range headers {
			headerValue = strings.ToLower(headerValue)
			headerKey = strings.ToLower(headerKey)
			for _, pattern := range patterns {
				if strings.Contains(headerValue, pattern) ||
					strings.Contains(headerKey, pattern) {
					return waf + " WAF"
				}
			}
		}
	}

	return ""
}

// DetectCloudProvider identifies cloud/hosting providers
func (d *Detector) DetectCloudProvider(ip, hostname, isp string) string {
	combinedInfo := strings.ToLower(ip + " " + hostname + " " + isp)

	cloudPatterns := map[string][]string{
		"Amazon AWS":      {"amazon", "aws", "ec2", "amazonaws"},
		"Google Cloud":    {"google", "gcp", "googlecloud"},
		"Microsoft Azure": {"azure", "microsoft"},
		"DigitalOcean":    {"digitalocean"},
		"Linode":          {"linode"},
		"Vultr":           {"vultr"},
		"Hetzner":         {"hetzner"},
		"OVH":             {"ovh"},
		"Alibaba Cloud":   {"alibaba", "alibabacloud"},
		"Oracle Cloud":    {"oracle"},
		"IBM Cloud":       {"ibm", "softlayer"},
		"Scaleway":        {"scaleway"},
	}

	for provider, patterns := range cloudPatterns {
		for _, pattern := range patterns {
			if strings.Contains(combinedInfo, pattern) {
				return provider
			}
		}
	}

	return ""
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
