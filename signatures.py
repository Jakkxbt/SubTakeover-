"""
Subdomain Takeover Signatures Database
Contains patterns and indicators for various cloud services and platforms
"""

TAKEOVER_SIGNATURES = {
    'GitHub Pages': {
        'cname_patterns': [
            '.github.io',
            'github.io'
        ],
        'content_patterns': [
            'there isn\'t a github pages site here.',
            'for root urls (like http://example.com/) you must provide an index.html file'
        ],
        'status_codes': [404]
    },
    
    'Heroku': {
        'cname_patterns': [
            '.herokuapp.com',
            'herokuapp.com',
            'herokussl.com'
        ],
        'content_patterns': [
            'no such app',
            'heroku | no such app',
            'application error'
        ],
        'status_codes': [404, 503]
    },
    
    'Amazon S3': {
        'cname_patterns': [
            '.s3.amazonaws.com',
            's3.amazonaws.com',
            '.s3-website',
            's3-website'
        ],
        'content_patterns': [
            'nosuchbucket',
            'the specified bucket does not exist',
            'nosuchkey'
        ],
        'status_codes': [404]
    },
    
    'Shopify': {
        'cname_patterns': [
            '.myshopify.com',
            'myshopify.com'
        ],
        'content_patterns': [
            'sorry, this shop is currently unavailable',
            'this shop is currently unavailable'
        ],
        'status_codes': [404]
    },
    
    'Fastly': {
        'cname_patterns': [
            '.fastly.com',
            'fastly.com'
        ],
        'content_patterns': [
            'fastly error: unknown domain',
            'unknown domain'
        ],
        'status_codes': [404]
    },
    
    'Ghost': {
        'cname_patterns': [
            '.ghost.io',
            'ghost.io'
        ],
        'content_patterns': [
            'the thing you were looking for is no longer here',
            'domain error'
        ],
        'status_codes': [404]
    },
    
    'Pantheon': {
        'cname_patterns': [
            '.pantheonsite.io',
            'pantheonsite.io'
        ],
        'content_patterns': [
            '404 error unknown site!',
            'unknown site'
        ],
        'status_codes': [404]
    },
    
    'Tumblr': {
        'cname_patterns': [
            '.tumblr.com',
            'tumblr.com'
        ],
        'content_patterns': [
            'whatever you were looking for doesn\'t currently exist at this address',
            'there\'s nothing here'
        ],
        'status_codes': [404]
    },
    
    'WordPress.com': {
        'cname_patterns': [
            '.wordpress.com',
            'wordpress.com'
        ],
        'content_patterns': [
            'do you want to register',
            'doesn\'t exist'
        ],
        'status_codes': [404]
    },
    
    'Bitbucket': {
        'cname_patterns': [
            '.bitbucket.org',
            'bitbucket.org'
        ],
        'content_patterns': [
            'repository not found',
            'the page you requested was not found'
        ],
        'status_codes': [404]
    },
    
    'Squarespace': {
        'cname_patterns': [
            '.squarespace.com',
            'squarespace.com'
        ],
        'content_patterns': [
            'no such account on squarespace',
            'this website is no longer available'
        ],
        'status_codes': [404]
    },
    
    'Surge.sh': {
        'cname_patterns': [
            '.surge.sh',
            'surge.sh'
        ],
        'content_patterns': [
            'project not found',
            'repository not found'
        ],
        'status_codes': [404]
    },
    
    'Zendesk': {
        'cname_patterns': [
            '.zendesk.com',
            'zendesk.com'
        ],
        'content_patterns': [
            'help center closed',
            'this help center no longer exists'
        ],
        'status_codes': [404]
    },
    
    'UserVoice': {
        'cname_patterns': [
            '.uservoice.com',
            'uservoice.com'
        ],
        'content_patterns': [
            'this uservoice subdomain is currently available!',
            'subdomain not found'
        ],
        'status_codes': [404]
    },
    
    'Webflow': {
        'cname_patterns': [
            '.webflow.io',
            'webflow.io'
        ],
        'content_patterns': [
            'the page you are looking for doesn\'t exist or has been moved',
            'page not found'
        ],
        'status_codes': [404]
    },
    
    'Landingi': {
        'cname_patterns': [
            '.landingi.com',
            'landingi.com'
        ],
        'content_patterns': [
            'it looks like you\'re lost',
            'page not found'
        ],
        'status_codes': [404]
    },
    
    'Netlify': {
        'cname_patterns': [
            '.netlify.app',
            '.netlify.com',
            'netlify.app',
            'netlify.com'
        ],
        'content_patterns': [
            'not found - request id',
            'page not found'
        ],
        'status_codes': [404]
    },
    
    'Vercel': {
        'cname_patterns': [
            '.vercel.app',
            'vercel.app'
        ],
        'content_patterns': [
            'the deployment could not be found',
            'deployment not found'
        ],
        'status_codes': [404]
    },
    
    'Azure': {
        'cname_patterns': [
            '.azurewebsites.net',
            'azurewebsites.net',
            '.cloudapp.net',
            'cloudapp.net'
        ],
        'content_patterns': [
            'error 404 - web app not found',
            'web app not found'
        ],
        'status_codes': [404]
    },
    
    'Firebase': {
        'cname_patterns': [
            '.firebaseapp.com',
            '.web.app',
            'firebaseapp.com',
            'web.app'
        ],
        'content_patterns': [
            'hosting: site not found',
            'site not found'
        ],
        'status_codes': [404]
    },
    
    'ClickFunnels': {
        'cname_patterns': [
            '.clickfunnels.com',
            'clickfunnels.com'
        ],
        'content_patterns': [
            'the page you were looking for doesn\'t exist',
            'page does not exist'
        ],
        'status_codes': [404]
    },
    
    'Intercom': {
        'cname_patterns': [
            '.custom.intercom.help',
            'custom.intercom.help'
        ],
        'content_patterns': [
            'uh oh. that page doesn\'t exist.',
            'page doesn\'t exist'
        ],
        'status_codes': [404]
    },
    
    'Webnode': {
        'cname_patterns': [
            '.webnode.com',
            'webnode.com'
        ],
        'content_patterns': [
            'invalid license',
            'page not found'
        ],
        'status_codes': [404]
    },
    
    'Unbounce': {
        'cname_patterns': [
            '.unbouncepages.com',
            'unbouncepages.com'
        ],
        'content_patterns': [
            'the requested url was not found on this server',
            'page not found'
        ],
        'status_codes': [404]
    }
}

# Additional patterns for edge cases
GENERIC_TAKEOVER_PATTERNS = {
    'content_patterns': [
        'domain not found',
        'subdomain not found',
        'site not found',
        'page not found',
        'this domain is not configured',
        'domain configuration error',
        'hosting error',
        'domain error',
        'not configured'
    ],
    'suspicious_redirects': [
        'parking',
        'domain-for-sale',
        'expired',
        'suspended'
    ]
}

def get_all_signatures():
    """Return all takeover signatures"""
    return TAKEOVER_SIGNATURES

def get_signature_by_service(service_name):
    """Get signature for a specific service"""
    return TAKEOVER_SIGNATURES.get(service_name, {})

def add_custom_signature(service_name, signature_data):
    """Add a custom signature (for extensibility)"""
    TAKEOVER_SIGNATURES[service_name] = signature_data

# Service detection based on CNAME patterns
def detect_service_from_cname(cname):
    """Detect service type from CNAME record"""
    cname_lower = cname.lower().rstrip('.')
    
    for service, signature in TAKEOVER_SIGNATURES.items():
        for pattern in signature.get('cname_patterns', []):
            if pattern.lower() in cname_lower:
                return service
                
    return 'Unknown Service'

# Risk scoring based on patterns
def calculate_risk_score(vulnerabilities):
    """Calculate overall risk score based on vulnerabilities found"""
    total_score = 0
    
    for vuln in vulnerabilities:
        if vuln['confidence'] == 'HIGH':
            total_score += 80
        elif vuln['confidence'] == 'MEDIUM':
            total_score += 50
        elif vuln['confidence'] == 'LOW':
            total_score += 20
            
    return min(total_score, 100)
