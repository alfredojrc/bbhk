"""Report templates for different platforms and vulnerability types."""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from jinja2 import Environment, BaseLoader, Template
from dataclasses import dataclass, field

@dataclass
class ReportTemplate:
    """Report template structure."""
    name: str
    platform: str
    vulnerability_type: str
    template: str
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)

class TemplateManager:
    """Manages report templates for different platforms."""
    
    def __init__(self):
        """Initialize template manager."""
        self.templates: Dict[str, ReportTemplate] = {}
        self.jinja_env = Environment(loader=BaseLoader())
        self._load_default_templates()
    
    def _load_default_templates(self):
        """Load default templates for common platforms and vulnerabilities."""
        
        # HackerOne XSS Template
        h1_xss_template = ReportTemplate(
            name="hackerone_xss",
            platform="hackerone",
            vulnerability_type="xss",
            template="""# Cross-Site Scripting (XSS) Vulnerability

## Summary
A {{ severity }} cross-site scripting vulnerability was discovered in the {{ parameter }} parameter of {{ url }}. This vulnerability allows an attacker to execute arbitrary JavaScript code in the context of other users' browsers.

## Vulnerability Details
- **Vulnerability Type:** Cross-Site Scripting (XSS)
- **Severity:** {{ severity.title() }}
- **Location:** {{ url }}
- **Parameter:** {{ parameter }}
- **HTTP Method:** {{ method | default('GET') }}

## Proof of Concept
1. Navigate to the following URL:
   ```
   {{ poc_url }}
   ```

2. The payload `{{ payload }}` is reflected in the response without proper encoding.

3. When the page loads, the JavaScript payload executes, demonstrating the XSS vulnerability.

## Impact
This vulnerability could allow an attacker to:
- Steal session cookies and hijack user accounts
- Perform actions on behalf of authenticated users
- Redirect users to malicious websites
- Deface the website content
- Steal sensitive information displayed on the page

## Reproduction Steps
{% for step in reproduction_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## Supporting Evidence
- **Request:**
  ```http
  {{ request_data }}
  ```

- **Response Excerpt:**
  ```html
  {{ response_excerpt }}
  ```

{% if screenshots %}
- **Screenshots:**
{% for screenshot in screenshots %}
  - {{ screenshot.description }}: [{{ screenshot.filename }}]({{ screenshot.url }})
{% endfor %}
{% endif %}

## Technical Details
- **Reflection Context:** {{ reflection_context }}
- **Encoding Bypasses:** {{ encoding_bypasses | default('None required') }}
- **Browser Tested:** {{ browser_tested | default('Chrome/Firefox') }}

## Remediation
To fix this vulnerability:
1. Implement proper output encoding for all user-controlled data
2. Use Content Security Policy (CSP) headers to prevent XSS attacks
3. Validate and sanitize all input parameters
4. Consider using a security-focused templating engine

Example fix for the affected parameter:
```javascript
// Before (vulnerable)
element.innerHTML = userInput;

// After (secure)
element.textContent = userInput;
// OR
element.innerHTML = escapeHtml(userInput);
```

## References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)

## Discovered By
{{ researcher_name | default('Security Researcher') }}
{{ discovery_date | default(now.strftime('%Y-%m-%d')) }}
""",
            required_fields=['severity', 'url', 'parameter', 'payload', 'poc_url', 'reproduction_steps'],
            optional_fields=['method', 'request_data', 'response_excerpt', 'screenshots', 
                           'reflection_context', 'encoding_bypasses', 'browser_tested', 
                           'researcher_name', 'discovery_date']
        )
        
        # HackerOne SQL Injection Template
        h1_sqli_template = ReportTemplate(
            name="hackerone_sqli",
            platform="hackerone",
            vulnerability_type="sqli",
            template="""# SQL Injection Vulnerability

## Summary
A {{ severity }} SQL injection vulnerability was discovered in the {{ parameter }} parameter of {{ url }}. This vulnerability allows an attacker to manipulate database queries and potentially extract sensitive data.

## Vulnerability Details
- **Vulnerability Type:** SQL Injection
- **Severity:** {{ severity.title() }}
- **Location:** {{ url }}
- **Parameter:** {{ parameter }}
- **HTTP Method:** {{ method | default('GET') }}
- **Database Type:** {{ database_type | default('Unknown') }}

## Proof of Concept
The following payload demonstrates the SQL injection vulnerability:

**Payload:** `{{ payload }}`

**Request:**
```http
{{ request_data }}
```

**Response showing SQL error:**
```
{{ sql_error }}
```

{% if time_based %}
## Time-Based SQL Injection
A time-based SQL injection was confirmed using the following payload:
- **Payload:** `{{ time_payload }}`
- **Response Time:** {{ response_time }} seconds (expected delay: {{ expected_delay }} seconds)
{% endif %}

## Impact
This SQL injection vulnerability could allow an attacker to:
- Extract sensitive data from the database
- Modify or delete database records
- Bypass authentication mechanisms
- Execute arbitrary SQL commands
- Potentially gain access to the underlying operating system

## Reproduction Steps
{% for step in reproduction_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## Technical Details
- **Injection Point:** {{ injection_point }}
- **SQL Query Context:** {{ query_context | default('WHERE clause') }}
- **Error-Based:** {{ 'Yes' if error_based else 'No' }}
- **Time-Based:** {{ 'Yes' if time_based else 'No' }}
- **Union-Based:** {{ 'Yes' if union_based else 'No' }}

{% if extracted_data %}
## Extracted Data Sample
```sql
{{ extracted_data }}
```
{% endif %}

## Remediation
To fix this SQL injection vulnerability:
1. Use parameterized queries (prepared statements) for all database interactions
2. Implement input validation and sanitization
3. Apply the principle of least privilege for database accounts
4. Enable database query logging and monitoring

**Example secure code:**
```python
# Vulnerable code
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Secure code
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

## References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## Discovered By
{{ researcher_name | default('Security Researcher') }}
{{ discovery_date | default(now.strftime('%Y-%m-%d')) }}
""",
            required_fields=['severity', 'url', 'parameter', 'payload', 'request_data', 'sql_error', 'reproduction_steps'],
            optional_fields=['method', 'database_type', 'time_based', 'time_payload', 'response_time', 
                           'expected_delay', 'injection_point', 'query_context', 'error_based', 
                           'union_based', 'extracted_data', 'researcher_name', 'discovery_date']
        )
        
        # Bugcrowd XSS Template
        bc_xss_template = ReportTemplate(
            name="bugcrowd_xss",
            platform="bugcrowd",
            vulnerability_type="xss",
            template="""## Vulnerability Summary
Cross-Site Scripting (XSS) vulnerability in {{ parameter }} parameter

## Vulnerability Details
**Vulnerability Type:** Cross-Site Scripting (XSS)
**Severity:** {{ severity.title() }}
**Affected URL:** {{ url }}
**Vulnerable Parameter:** {{ parameter }}

## Steps to Reproduce
{% for step in reproduction_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## Proof of Concept
```
{{ poc_url }}
```

The above URL contains the payload: `{{ payload }}`

## Impact
- Session hijacking through cookie theft
- Unauthorized actions performed on behalf of users
- Potential data exfiltration
- Website defacement

## Evidence
{{ request_response_evidence }}

{% if screenshots %}
**Screenshots:**
{% for screenshot in screenshots %}
- {{ screenshot.description }}
{% endfor %}
{% endif %}

## Remediation Recommendations
1. Implement proper output encoding for all dynamic content
2. Use Content Security Policy (CSP) headers
3. Validate and sanitize user input
4. Use secure coding practices for DOM manipulation

## References
- OWASP XSS Prevention: https://owasp.org/www-community/attacks/xss/
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
""",
            required_fields=['severity', 'url', 'parameter', 'reproduction_steps', 'poc_url', 'payload'],
            optional_fields=['request_response_evidence', 'screenshots']
        )
        
        # Generic vulnerability template
        generic_template = ReportTemplate(
            name="generic_vulnerability",
            platform="generic",
            vulnerability_type="generic",
            template="""# {{ vulnerability_type.title() }} Vulnerability Report

## Executive Summary
A {{ severity }} {{ vulnerability_type }} vulnerability was identified in {{ target }}.

## Vulnerability Details
- **Type:** {{ vulnerability_type.title() }}
- **Severity:** {{ severity.title() }}
- **Location:** {{ target }}
- **Discovery Date:** {{ discovery_date | default(now.strftime('%Y-%m-%d')) }}

## Description
{{ description }}

## Impact Assessment
{{ impact }}

## Proof of Concept
{{ proof_of_concept }}

## Reproduction Steps
{% for step in reproduction_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## Technical Details
{{ technical_details }}

## Remediation
{{ remediation }}

{% if references %}
## References
{% for ref in references %}
- {{ ref }}
{% endfor %}
{% endif %}

---
*Report generated by Bug Bounty Framework*
""",
            required_fields=['vulnerability_type', 'severity', 'target', 'description', 'impact', 'proof_of_concept', 'reproduction_steps'],
            optional_fields=['discovery_date', 'technical_details', 'remediation', 'references']
        )
        
        # Store templates
        self.templates['hackerone_xss'] = h1_xss_template
        self.templates['hackerone_sqli'] = h1_sqli_template
        self.templates['bugcrowd_xss'] = bc_xss_template
        self.templates['generic'] = generic_template
    
    def get_template(self, platform: str, vulnerability_type: str) -> Optional[ReportTemplate]:
        """Get template for specific platform and vulnerability type."""
        # Try exact match first
        template_key = f"{platform}_{vulnerability_type}"
        if template_key in self.templates:
            return self.templates[template_key]
        
        # Try platform-specific generic template
        platform_generic = f"{platform}_generic"
        if platform_generic in self.templates:
            return self.templates[platform_generic]
        
        # Fall back to generic template
        return self.templates.get('generic')
    
    def list_templates(self) -> List[Dict[str, str]]:
        """List all available templates."""
        return [
            {
                'name': template.name,
                'platform': template.platform,
                'vulnerability_type': template.vulnerability_type,
                'required_fields': template.required_fields,
                'optional_fields': template.optional_fields
            }
            for template in self.templates.values()
        ]
    
    def add_custom_template(self, template: ReportTemplate):
        """Add a custom template."""
        self.templates[template.name] = template
    
    def render_template(self, template_name: str, data: Dict[str, Any]) -> str:
        """Render a template with provided data."""
        template = self.templates.get(template_name)
        if not template:
            raise ValueError(f"Template {template_name} not found")
        
        # Check required fields
        missing_fields = []
        for field in template.required_fields:
            if field not in data or data[field] is None:
                missing_fields.append(field)
        
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # Add current timestamp for templates
        data['now'] = datetime.now(timezone.utc)
        
        # Render template
        jinja_template = self.jinja_env.from_string(template.template)
        return jinja_template.render(**data)
    
    def validate_template_data(self, template_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate template data and return validation results."""
        template = self.templates.get(template_name)
        if not template:
            return {'valid': False, 'error': f"Template {template_name} not found"}
        
        missing_required = []
        for field in template.required_fields:
            if field not in data or data[field] is None or data[field] == '':
                missing_required.append(field)
        
        missing_optional = []
        for field in template.optional_fields:
            if field not in data:
                missing_optional.append(field)
        
        return {
            'valid': len(missing_required) == 0,
            'missing_required': missing_required,
            'missing_optional': missing_optional,
            'provided_fields': list(data.keys())
        }

# Global template manager
template_manager = TemplateManager()