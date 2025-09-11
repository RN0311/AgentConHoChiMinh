import asyncio
import json
import logging
import re
import ast
import subprocess
import tempfile
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import hashlib
import time

async def slow_print(*args, delay: float = 0.2, **kwargs):
    print(*args, **kwargs)
    await asyncio.sleep(delay)


try:
    import ollama
    VALIDATION_OLLAMA_AVAILABLE = True
    print("✅ Ollama package available for AI validation")
except ImportError:
    VALIDATION_OLLAMA_AVAILABLE = False
    print("❌ Ollama not installed - using rule-based validation only")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting" 
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_CRYPTO = "insecure_cryptography"
    AUTHENTICATION_BYPASS = "auth_bypass"
    INSECURE_DESERIALIZATION = "insecure_deserialization"

class SeverityLevel(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

class ValidationStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    MANUAL_REVIEW = "manual_review"

@dataclass
class SecurityTest:
    test_id: str
    name: str
    test_type: str
    payload: str
    expected_result: str
    description: str

@dataclass
class SyntaxValidationResult:
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    ast_tree: Optional[Any] = None

@dataclass
class SecurityValidationResult:
    vulnerability_type: VulnerabilityType
    is_fixed: bool
    test_results: List[Dict] = field(default_factory=list)
    security_score: float = 0.0
    remaining_issues: List[str] = field(default_factory=list)
    improvements: List[str] = field(default_factory=list)

@dataclass
class ComprehensiveValidationResult:
    patch_id: str
    status: ValidationStatus
    syntax_validation: SyntaxValidationResult
    security_validation: SecurityValidationResult
    confidence_score: float
    execution_safe: bool
    performance_impact: str
    recommendations: List[str] = field(default_factory=list)
    validation_timestamp: datetime = field(default_factory=datetime.now)
    ai_analysis: Optional[str] = None

@dataclass
class PatchResult:
    """Redefining PatchResult for compatibility with patch generation agent"""
    vulnerability_id: str
    original_code: str
    patched_code: str
    explanation: str
    confidence_score: float
    patch_type: str
    test_cases: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.now)

class SecurityTestSuite:
    """Comprehensive security test suite for different vulnerability types"""
    
    def __init__(self):
        self.test_suites = self._initialize_test_suites()
    
    def _initialize_test_suites(self) -> Dict[VulnerabilityType, List[SecurityTest]]:
        return {
            VulnerabilityType.SQL_INJECTION: [
                SecurityTest(
                    test_id="sql_basic_injection",
                    name="Basic SQL Injection Test",
                    test_type="payload_injection",
                    payload="' OR '1'='1",
                    expected_result="should_be_escaped_or_parameterized",
                    description="Tests basic SQL injection with OR condition"
                ),
                SecurityTest(
                    test_id="sql_union_injection", 
                    name="UNION SQL Injection Test",
                    test_type="payload_injection",
                    payload="' UNION SELECT * FROM users--",
                    expected_result="should_be_escaped_or_parameterized",
                    description="Tests UNION-based SQL injection"
                ),
                SecurityTest(
                    test_id="sql_time_based",
                    name="Time-based SQL Injection Test", 
                    test_type="payload_injection",
                    payload="'; WAITFOR DELAY '00:00:10'--",
                    expected_result="should_be_escaped_or_parameterized",
                    description="Tests time-based blind SQL injection"
                )
            ],
            
            VulnerabilityType.XSS: [
                SecurityTest(
                    test_id="xss_script_injection",
                    name="Script Tag XSS Test",
                    test_type="payload_injection", 
                    payload="<script>alert('XSS')</script>",
                    expected_result="should_be_escaped_or_sanitized",
                    description="Tests basic script tag injection"
                ),
                SecurityTest(
                    test_id="xss_event_handler",
                    name="Event Handler XSS Test",
                    test_type="payload_injection",
                    payload="<img src=x onerror=alert('XSS')>",
                    expected_result="should_be_escaped_or_sanitized", 
                    description="Tests event handler-based XSS"
                ),
                SecurityTest(
                    test_id="xss_javascript_url",
                    name="JavaScript URL XSS Test",
                    test_type="payload_injection",
                    payload="javascript:alert('XSS')",
                    expected_result="should_be_escaped_or_sanitized",
                    description="Tests JavaScript URL scheme injection"
                )
            ],
            
            VulnerabilityType.COMMAND_INJECTION: [
                SecurityTest(
                    test_id="cmd_semicolon_injection",
                    name="Semicolon Command Injection Test",
                    test_type="payload_injection",
                    payload="127.0.0.1; cat /etc/passwd",
                    expected_result="should_be_validated_or_escaped",
                    description="Tests command injection using semicolon"
                ),
                SecurityTest(
                    test_id="cmd_pipe_injection", 
                    name="Pipe Command Injection Test",
                    test_type="payload_injection",
                    payload="127.0.0.1 | whoami",
                    expected_result="should_be_validated_or_escaped",
                    description="Tests command injection using pipe"
                ),
                SecurityTest(
                    test_id="cmd_backtick_injection",
                    name="Backtick Command Injection Test",
                    test_type="payload_injection", 
                    payload="127.0.0.1 `whoami`",
                    expected_result="should_be_validated_or_escaped",
                    description="Tests command injection using backticks"
                )
            ],
            
            VulnerabilityType.PATH_TRAVERSAL: [
                SecurityTest(
                    test_id="path_dot_dot_slash",
                    name="Directory Traversal Test",
                    test_type="payload_injection",
                    payload="../../../etc/passwd",
                    expected_result="should_be_blocked_or_sanitized",
                    description="Tests basic directory traversal"
                ),
                SecurityTest(
                    test_id="path_encoded_traversal",
                    name="URL Encoded Path Traversal Test", 
                    test_type="payload_injection",
                    payload="..%2f..%2f..%2fetc%2fpasswd",
                    expected_result="should_be_blocked_or_sanitized",
                    description="Tests URL-encoded directory traversal"
                ),
                SecurityTest(
                    test_id="path_null_byte",
                    name="Null Byte Path Traversal Test",
                    test_type="payload_injection",
                    payload="../../../etc/passwd%00.jpg",
                    expected_result="should_be_blocked_or_sanitized", 
                    description="Tests null byte injection in file paths"
                )
            ],
            
            VulnerabilityType.INSECURE_CRYPTO: [
                SecurityTest(
                    test_id="crypto_weak_hash",
                    name="Weak Hash Algorithm Test",
                    test_type="algorithm_check",
                    payload="md5,sha1",
                    expected_result="should_use_strong_algorithms",
                    description="Tests for weak cryptographic hash functions"
                ),
                SecurityTest(
                    test_id="crypto_hardcoded_key",
                    name="Hardcoded Key Test",
                    test_type="pattern_check",
                    payload="secret_key,password,api_key",
                    expected_result="should_use_environment_variables",
                    description="Tests for hardcoded cryptographic keys"
                )
            ],
            
            VulnerabilityType.AUTHENTICATION_BYPASS: [
                SecurityTest(
                    test_id="auth_timing_attack",
                    name="Timing Attack Test",
                    test_type="timing_analysis",
                    payload="test_password", 
                    expected_result="should_use_constant_time_comparison",
                    description="Tests for timing attack vulnerabilities"
                ),
                SecurityTest(
                    test_id="auth_weak_jwt",
                    name="Weak JWT Secret Test",
                    test_type="pattern_check",
                    payload="secret,123,password",
                    expected_result="should_use_strong_random_secret",
                    description="Tests for weak JWT secrets"
                )
            ]
        }
    
    def get_tests_for_vulnerability(self, vuln_type: VulnerabilityType) -> List[SecurityTest]:
        """Get security tests for a specific vulnerability type"""
        return self.test_suites.get(vuln_type, [])

class ValidationEngine:
    
    def __init__(self, ai_model: str = "deepseek-r1:latest"):
        self.ai_model = ai_model
        self.use_ai = VALIDATION_OLLAMA_AVAILABLE
        self.test_suite = SecurityTestSuite()
        
        if self.use_ai:
            self._check_ai_model()
        
        self.secure_patterns = self._initialize_secure_patterns()
        self.insecure_patterns = self._initialize_insecure_patterns()
    
    def _check_ai_model(self):
        """Check if AI model is available for enhanced validation"""
        try:
            models_response = ollama.list()
            
            if hasattr(models_response, 'models'):
                available_models = [m.model for m in models_response.models]
            else:
                available_models = [m.get('model', '') for m in models_response]
            
            if any(self.ai_model in model for model in available_models):
                logger.info(f"✅ AI validation model available: {self.ai_model}")
            else:
                logger.warning(f"❌ AI model '{self.ai_model}' not found")
                self.use_ai = False
                
        except Exception as e:
            logger.error(f"Failed to connect to Ollama for validation: {e}")
            self.use_ai = False
    
    def _initialize_secure_patterns(self) -> Dict[VulnerabilityType, List[str]]:
        return {
            VulnerabilityType.SQL_INJECTION: [
                r'\.execute\s*\(\s*["\'][^"\']*["\']\s*,\s*\([^)]+\)\s*\)',  # Parameterized queries
                r'cursor\.execute\s*\(\s*["\'][^"\']*\?\s*["\']',  # SQLite placeholders
                r'\.prepare\s*\(',  # Prepared statements
                r'Session\.query\(',  # ORM usage
            ],
            VulnerabilityType.XSS: [
                r'\.textContent\s*=',  # Safe DOM assignment
                r'escape\s*\(',  # Explicit escaping
                r'sanitize\s*\(',  # Sanitization functions
                r'DOMPurify\.sanitize\s*\(',  # DOMPurify usage
                r'html\.escape\s*\(',  # Python HTML escaping
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                r'subprocess\.run\s*\(\s*\[',  # List-based subprocess calls
                r'shell\s*=\s*False',  # Explicit shell=False
                r'shlex\.quote\s*\(',  # Shell escaping
                r'validate_input\s*\(',  # Input validation
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                r'os\.path\.join\s*\(',  # Safe path joining
                r'os\.path\.basename\s*\(',  # Path sanitization
                r'os\.path\.realpath\s*\(',  # Path resolution
                r'pathlib\.Path\(',  # Modern path handling
            ],
            VulnerabilityType.INSECURE_CRYPTO: [
                r'bcrypt\.hashpw\s*\(',  # Bcrypt usage
                r'scrypt\s*\(',  # Scrypt usage
                r'pbkdf2\s*\(',  # PBKDF2 usage
                r'hashlib\.sha256\s*\(',  # Strong hash functions
                r'secrets\.token_',  # Secure random generation
            ],
            VulnerabilityType.AUTHENTICATION_BYPASS: [
                r'hmac\.compare_digest\s*\(',  # Constant-time comparison
                r'secrets\.compare_digest\s*\(',  # Secure comparison
                r'os\.environ\.get\s*\(',  # Environment variables
                r'random\.SystemRandom\s*\(',  # Cryptographically secure random
            ]
        }
    
    def _initialize_insecure_patterns(self) -> Dict[VulnerabilityType, List[str]]:
        """Initialize patterns that indicate potentially insecure code"""
        return {
            VulnerabilityType.SQL_INJECTION: [
                r'["\'].*\+.*["\']',  # String concatenation
                r'f["\'].*\{.*\}.*["\']',  # f-string formatting
                r'%.*%\s*\(',  # % formatting
                r'\.format\s*\(',  # .format() method
            ],
            VulnerabilityType.XSS: [
                r'\.innerHTML\s*=',  # Direct innerHTML assignment
                r'document\.write\s*\(',  # document.write usage
                r'\+.*<.*>.*\+',  # HTML concatenation
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                r'os\.system\s*\(',  # os.system usage
                r'shell\s*=\s*True',  # shell=True parameter
                r'subprocess\.call\s*\([^,]*,\s*shell\s*=\s*True',  # subprocess with shell=True
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                r'open\s*\(\s*[^,]*\+',  # File path concatenation
                r'["\'].*\/.*["\']\s*\+',  # Path string concatenation
                r'request\.[^.]*\.get\([^)]*\)',  # Direct request parameter usage
            ],
            VulnerabilityType.INSECURE_CRYPTO: [
                r'hashlib\.md5\s*\(',  # MD5 usage
                r'hashlib\.sha1\s*\(',  # SHA1 usage
                r'["\'][^"\']*secret[^"\']*["\']',  # Hardcoded secrets
            ],
            VulnerabilityType.AUTHENTICATION_BYPASS: [
                r'==.*password',  # Direct password comparison
                r'jwt\.encode\s*\([^,]*,\s*["\'][^"\']*["\']',  # Weak JWT secrets
            ]
        }
    
    async def validate_patch(self, patch: PatchResult, vulnerability_type: VulnerabilityType) -> ComprehensiveValidationResult:

        logger.info(f"🔍 Starting comprehensive validation for patch {patch.vulnerability_id}")
        
        syntax_result = self._validate_syntax(patch.patched_code, patch.vulnerability_id)
        
        security_result = await self._validate_security(patch, vulnerability_type)
        
        ai_analysis = None
        if self.use_ai:
            try:
                ai_analysis = await self._ai_enhanced_validation(patch, vulnerability_type)
            except Exception as e:
                logger.warning(f"AI validation failed: {e}")
        
        overall_status = self._determine_overall_status(syntax_result, security_result)
        confidence_score = self._calculate_confidence(syntax_result, security_result, ai_analysis)
        
        recommendations = self._generate_recommendations(syntax_result, security_result, patch)
        
        return ComprehensiveValidationResult(
            patch_id=patch.vulnerability_id,
            status=overall_status,
            syntax_validation=syntax_result,
            security_validation=security_result,
            confidence_score=confidence_score,
            execution_safe=syntax_result.is_valid and security_result.is_fixed,
            performance_impact=self._assess_performance_impact(patch),
            recommendations=recommendations,
            ai_analysis=ai_analysis
        )
    
    def _validate_syntax(self, code: str, patch_id: str) -> SyntaxValidationResult:
        """Validate syntax of patched code"""
        
        errors = []
        warnings = []
        ast_tree = None
        
        # Python syntax validation
        if any(lang in patch_id.lower() for lang in ['py', 'python']):
            try:
                ast_tree = ast.parse(code)
                logger.info("✅ Python syntax validation passed")
            except SyntaxError as e:
                errors.append(f"Python syntax error: {e}")
                logger.error(f"❌ Python syntax error: {e}")
            except Exception as e:
                warnings.append(f"Python validation warning: {e}")
        
        # JavaScript syntax validation (basic)
        if any(lang in patch_id.lower() for lang in ['js', 'javascript']):
            # Basic JavaScript validation patterns
            js_issues = []
            
            # Check for common JS syntax issues
            if code.count('(') != code.count(')'):
                js_issues.append("Mismatched parentheses")
            if code.count('{') != code.count('}'):
                js_issues.append("Mismatched braces")
            if code.count('[') != code.count(']'):
                js_issues.append("Mismatched brackets")
            
            if js_issues:
                errors.extend(js_issues)
            else:
                logger.info("✅ Basic JavaScript syntax validation passed")
        
        # SQL syntax validation (basic)
        if 'sql' in patch_id.lower():
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP']
            if not any(keyword.lower() in code.lower() for keyword in sql_keywords):
                warnings.append("No SQL keywords detected - verify this is SQL code")
        
        return SyntaxValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            ast_tree=ast_tree
        )
    
    async def _validate_security(self, patch: PatchResult, vuln_type: VulnerabilityType) -> SecurityValidationResult:
        """Comprehensive security validation"""
        
        logger.info(f"🛡️ Running security validation for {vuln_type.value}")
        
        test_results = []
        improvements = []
        remaining_issues = []
        
        # Get relevant security tests
        security_tests = self.test_suite.get_tests_for_vulnerability(vuln_type)
        
        # Pattern-based security analysis
        secure_patterns = self.secure_patterns.get(vuln_type, [])
        insecure_patterns = self.insecure_patterns.get(vuln_type, [])
        
        # Check for secure patterns
        secure_matches = 0
        for pattern in secure_patterns:
            if re.search(pattern, patch.patched_code, re.IGNORECASE):
                secure_matches += 1
                improvements.append(f"Found secure pattern: {pattern}")
        
        # Check for remaining insecure patterns  
        insecure_matches = 0
        for pattern in insecure_patterns:
            if re.search(pattern, patch.patched_code, re.IGNORECASE):
                insecure_matches += 1
                remaining_issues.append(f"Potentially insecure pattern: {pattern}")
        
        # Run specific security tests
        for test in security_tests:
            test_result = await self._run_security_test(test, patch)
            test_results.append(test_result)
        
        # Calculate security score
        total_patterns = len(secure_patterns) + len(insecure_patterns)
        if total_patterns > 0:
            security_score = (secure_matches + (len(insecure_patterns) - insecure_matches)) / total_patterns
            security_score = max(0.0, min(1.0, security_score))  # Clamp to [0,1]
        else:
            security_score = 0.5  # Neutral score when no patterns available
        
        # Determine if vulnerability is fixed
        is_fixed = (
            secure_matches > 0 and  # Has at least one secure pattern
            insecure_matches == 0 and  # No insecure patterns remain
            all(test.get('passed', False) for test in test_results if test.get('critical', False))
        )
        
        return SecurityValidationResult(
            vulnerability_type=vuln_type,
            is_fixed=is_fixed,
            test_results=test_results,
            security_score=security_score,
            remaining_issues=remaining_issues,
            improvements=improvements
        )
    
    async def _run_security_test(self, test: SecurityTest, patch: PatchResult) -> Dict:
        """Run a specific security test against the patched code"""
        
        test_result = {
            'test_id': test.test_id,
            'name': test.name,
            'type': test.test_type,
            'passed': False,
            'details': '',
            'critical': False
        }
        
        if test.test_type == "payload_injection":
            # Check if payload would be handled securely
            test_result['passed'] = self._test_payload_injection(test.payload, patch.patched_code, patch.vulnerability_id)
            test_result['critical'] = True
            test_result['details'] = f"Payload '{test.payload}' injection test"
        
        elif test.test_type == "pattern_check":
            # Check for specific patterns in code
            test_result['passed'] = self._test_pattern_check(test.payload, patch.patched_code)
            test_result['details'] = f"Pattern check for: {test.payload}"
        
        elif test.test_type == "algorithm_check":
            # Check cryptographic algorithms
            test_result['passed'] = self._test_algorithm_strength(test.payload, patch.patched_code)
            test_result['details'] = f"Algorithm strength check"
        
        elif test.test_type == "timing_analysis":
            # Basic timing attack check
            test_result['passed'] = self._test_timing_safety(patch.patched_code)
            test_result['details'] = "Timing attack resistance check"
        
        return test_result
    
    def _test_payload_injection(self, payload: str, code: str, vuln_id: str) -> bool:
        """Test if malicious payload would be handled securely"""
        
        # SQL Injection tests
        if 'sql' in vuln_id.lower():
            # Check for parameterized queries or prepared statements
            secure_sql_patterns = [
                r'\.execute\s*\([^,]+,\s*\(',  # Parameterized
                r'\?',  # SQL placeholders
                r'%\(.*\)s',  # Named parameters
            ]
            return any(re.search(pattern, code, re.IGNORECASE) for pattern in secure_sql_patterns)
        
        # XSS tests
        if 'xss' in vuln_id.lower():
            # Check for proper escaping or sanitization
            secure_xss_patterns = [
                r'textContent',  # Safe DOM manipulation
                r'escape\s*\(',  # Explicit escaping
                r'sanitize\s*\(',  # Sanitization
            ]
            return any(re.search(pattern, code, re.IGNORECASE) for pattern in secure_xss_patterns)
        
        # Command Injection tests
        if 'cmd' in vuln_id.lower():
            # Check for safe command execution
            secure_cmd_patterns = [
                r'subprocess\.run\s*\(\s*\[',  # List-based calls
                r'shell\s*=\s*False',  # No shell
                r'shlex\.quote',  # Proper escaping
            ]
            return any(re.search(pattern, code, re.IGNORECASE) for pattern in secure_cmd_patterns)
        
        # Path Traversal tests
        if 'path' in vuln_id.lower():
            # Check for path sanitization
            secure_path_patterns = [
                r'os\.path\.join',  # Safe joining
                r'os\.path\.basename',  # Basename only
                r'realpath',  # Path resolution
            ]
            return any(re.search(pattern, code, re.IGNORECASE) for pattern in secure_path_patterns)
        
        return False
    
    def _test_pattern_check(self, patterns: str, code: str) -> bool:
        """Test for presence/absence of specific patterns"""
        pattern_list = patterns.split(',')
        
        # For security tests, absence of weak patterns is good
        return not any(pattern.strip() in code.lower() for pattern in pattern_list)
    
    def _test_algorithm_strength(self, weak_algorithms: str, code: str) -> bool:
        """Test cryptographic algorithm strength"""
        weak_algos = weak_algorithms.split(',')
        
        # Check if weak algorithms are still present
        has_weak = any(algo.strip() in code.lower() for algo in weak_algos)
        
        # Check for strong alternatives
        strong_patterns = ['bcrypt', 'scrypt', 'pbkdf2', 'sha256', 'sha512']
        has_strong = any(pattern in code.lower() for pattern in strong_patterns)
        
        return not has_weak and has_strong
    
    def _test_timing_safety(self, code: str) -> bool:
        """Test for timing attack resistance"""
        
        # Check for constant-time comparison functions
        timing_safe_patterns = [
            r'hmac\.compare_digest',
            r'secrets\.compare_digest', 
            r'constant_time_compare',
        ]
        
        # Check for potentially vulnerable direct comparisons
        timing_vulnerable_patterns = [
            r'==.*password',
            r'password\s*==',
            r'if.*password.*==',
        ]
        
        has_safe_comparison = any(re.search(pattern, code, re.IGNORECASE) for pattern in timing_safe_patterns)
        has_vulnerable_comparison = any(re.search(pattern, code, re.IGNORECASE) for pattern in timing_vulnerable_patterns)
        
        return has_safe_comparison and not has_vulnerable_comparison
    
    async def _ai_enhanced_validation(self, patch: PatchResult, vuln_type: VulnerabilityType) -> str:
        """Use AI to provide enhanced validation analysis"""
        
        prompt = f"""You are a senior cybersecurity expert reviewing a security patch.

**PATCH DETAILS:**
- Vulnerability ID: {patch.vulnerability_id}
- Type: {vuln_type.value}
- Patch Type: {patch.patch_type}
- Confidence: {patch.confidence_score}

**ORIGINAL VULNERABLE CODE:**
```
{patch.original_code}
```

**PATCHED CODE:**
```
{patch.patched_code}
```

**PATCH EXPLANATION:**
{patch.explanation}

**VALIDATION TASK:**
Provide a comprehensive security analysis of this patch. Focus on:

1. **Security Effectiveness**: Does the patch fully address the vulnerability?
2. **Implementation Quality**: Is the fix implemented correctly and securely?
3. **Completeness**: Are there any edge cases or additional security concerns?
4. **Best Practices**: Does the patch follow security best practices?
5. **Potential Issues**: Any remaining vulnerabilities or new issues introduced?

**RESPONSE FORMAT:**
Provide a structured analysis in this format:

SECURITY_ASSESSMENT: [SECURE/PARTIALLY_SECURE/INSECURE]
CONFIDENCE: [0.0-1.0]

ANALYSIS:
- Effectiveness: [detailed analysis]
- Implementation: [quality assessment]  
- Completeness: [gap analysis]
- Best Practices: [compliance check]
- Issues: [remaining concerns]

RECOMMENDATION: [APPROVE/APPROVE_WITH_WARNINGS/REJECT/MANUAL_REVIEW]

Be thorough and critical in your analysis."""
        
        try:
            response = ollama.chat(
                model=self.ai_model,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.1,
                    "top_k": 10,
                    "top_p": 0.9
                }
            )
            
            return response['message']['content']
            
        except Exception as e:
            logger.error(f"AI validation failed: {e}")
            return f"AI validation unavailable: {e}"
    
    def _determine_overall_status(self, syntax: SyntaxValidationResult, security: SecurityValidationResult) -> ValidationStatus:
        """Determine overall validation status"""
        
        if not syntax.is_valid:
            return ValidationStatus.FAILED
        
        if not security.is_fixed:
            if security.security_score < 0.3:
                return ValidationStatus.FAILED
            elif security.security_score < 0.7:
                return ValidationStatus.WARNING
            else:
                return ValidationStatus.MANUAL_REVIEW
        
        if security.remaining_issues:
            return ValidationStatus.WARNING
        
        return ValidationStatus.PASSED
    
    def _calculate_confidence(self, syntax: SyntaxValidationResult, security: SecurityValidationResult, ai_analysis: Optional[str]) -> float:
        """Calculate overall confidence score"""
        
        # Base confidence from syntax validation
        syntax_confidence = 1.0 if syntax.is_valid else 0.2
        
        # Security confidence
        security_confidence = security.security_score
        
        # AI confidence boost (if available)
        ai_confidence_boost = 0.0
        if ai_analysis and "CONFIDENCE:" in ai_analysis:
            try:
                # Extract AI confidence from response
                confidence_match = re.search(r'CONFIDENCE:\s*([\d.]+)', ai_analysis)
                if confidence_match:
                    ai_confidence = float(confidence_match.group(1))
                    ai_confidence_boost = ai_confidence * 0.2  # Weight AI input at 20%
            except:
                pass
        
        # Weighted combination
        base_confidence = (syntax_confidence * 0.3) + (security_confidence * 0.7)
        final_confidence = min(1.0, base_confidence + ai_confidence_boost)
        
        return final_confidence
    
    def _assess_performance_impact(self, patch: PatchResult) -> str:
        """Assess potential performance impact of the patch"""
        
        impact_indicators = {
            "high": ["bcrypt", "scrypt", "pbkdf2", "heavy_validation"],
            "medium": ["regex", "sanitize", "validate", "hash"],
            "low": ["parameterized", "escape", "textContent", "basename"]
        }
        
        code_lower = patch.patched_code.lower()
        
        for impact_level, indicators in impact_indicators.items():
            if any(indicator in code_lower for indicator in indicators):
                return impact_level
        
        return "minimal"
    
    def _generate_recommendations(self, syntax: SyntaxValidationResult, security: SecurityValidationResult, patch: PatchResult) -> List[str]:
        
        recommendations = []
        
        # Syntax recommendations
        if syntax.errors:
            recommendations.append("❌ Fix syntax errors before deployment")
            recommendations.extend([f"  • {error}" for error in syntax.errors])
        
        if syntax.warnings:
            recommendations.append("⚠️ Review syntax warnings")
            recommendations.extend([f"  • {warning}" for warning in syntax.warnings])
        
        # Security recommendations
        if security.remaining_issues:
            recommendations.append("🛡️ Address remaining security issues")
            recommendations.extend([f"  • {issue}" for issue in security.remaining_issues])
        
        if not security.is_fixed:
            recommendations.append("⚡ Vulnerability not fully addressed - requires additional fixes")
        
        if security.security_score < 0.8:
            recommendations.append("📊 Consider additional security hardening")
        
        # Best practice recommendations
        if patch.confidence_score < 0.8:
            recommendations.append("🔍 Manual code review recommended due to low confidence")
        
        if "TODO" in patch.patched_code or "FIXME" in patch.patched_code:
            recommendations.append("📝 Complete all TODO/FIXME comments")
        
        # Performance recommendations
        performance_impact = self._assess_performance_impact(patch)
        if performance_impact in ["high", "medium"]:
            recommendations.append(f"⚡ Monitor performance impact ({performance_impact})")
        
        return recommendations if recommendations else ["✅ No specific recommendations - patch looks good"]

class ValidationTestDataset:
    """Test dataset with sample patches for validation testing"""
    
    def __init__(self):
        self.test_patches = self._create_test_patches()
    
    def _create_test_patches(self) -> List[PatchResult]:
        """Create sample patches for testing validation"""
        
        return [
            # Good SQL Injection fix
            PatchResult(
                vulnerability_id="sql_01",
                original_code='query = "SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + password + "\'"',
                patched_code='cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))',
                explanation="Fixed SQL injection by using parameterized query with placeholders",
                confidence_score=0.95,
                patch_type="parameterized_query"
            ),
            
            # Partially fixed SQL injection (still vulnerable)
            PatchResult(
                vulnerability_id="sql_02", 
                original_code='cursor.execute(f"DELETE FROM posts WHERE id = {post_id} AND user_id = {user_id}")',
                patched_code='cursor.execute("DELETE FROM posts WHERE id = " + str(post_id) + " AND user_id = " + str(user_id))',
                explanation="Removed f-string but still using concatenation",
                confidence_score=0.3,
                patch_type="string_concatenation"
            ),
            
            # Good XSS fix
            PatchResult(
                vulnerability_id="xss_01",
                original_code='document.getElementById("content").innerHTML = userInput;',
                patched_code='document.getElementById("content").textContent = userInput;',
                explanation="Fixed XSS by using textContent instead of innerHTML",
                confidence_score=0.9,
                patch_type="safe_dom_manipulation"
            ),
            
            # Good command injection fix
            PatchResult(
                vulnerability_id="cmd_01",
                original_code='os.system("ping -c 4 " + user_ip)',
                patched_code='import subprocess; subprocess.run(["ping", "-c", "4", validated_ip], check=True)',
                explanation="Fixed command injection using subprocess with list arguments",
                confidence_score=0.92,
                patch_type="subprocess_security"
            ),
            
            # Bad crypto fix (still weak)
            PatchResult(
                vulnerability_id="crypto_01",
                original_code='password_hash = hashlib.md5(password.encode()).hexdigest()',
                patched_code='password_hash = hashlib.sha1(password.encode()).hexdigest()',
                explanation="Upgraded from MD5 to SHA1",
                confidence_score=0.4,
                patch_type="hash_upgrade"
            ),
            
            # Good crypto fix
            PatchResult(
                vulnerability_id="crypto_02",
                original_code='password_hash = hashlib.sha1(str(time.time()).encode()).hexdigest()',
                patched_code='import bcrypt; password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
                explanation="Fixed weak hashing by using bcrypt with salt",
                confidence_score=0.95,
                patch_type="strong_hashing"
            ),
        ]
    
    def get_all_patches(self) -> List[PatchResult]:
        return self.test_patches

async def demo_comprehensive_validation():
    """Comprehensive demonstration of the validation system"""
    
    await slow_print("🔍 COMPREHENSIVE PATCH VALIDATION DEMO")
    await slow_print("=" * 60)

    # Initialize validation engine
    validation_engine = ValidationEngine(ai_model="deepseek-r1:latest")
    test_dataset = ValidationTestDataset()
    
    # Vulnerability type mapping for test patches
    vuln_type_mapping = {
        "sql_01": VulnerabilityType.SQL_INJECTION,
        "sql_02": VulnerabilityType.SQL_INJECTION,
        "xss_01": VulnerabilityType.XSS,
        "cmd_01": VulnerabilityType.COMMAND_INJECTION,
        "crypto_01": VulnerabilityType.INSECURE_CRYPTO,
        "crypto_02": VulnerabilityType.INSECURE_CRYPTO,
    }
    
    validation_results = []
    
    # Validate each test patch
    for i, patch in enumerate(test_dataset.get_all_patches(), 1):
        vuln_type = vuln_type_mapping.get(patch.vulnerability_id, VulnerabilityType.SQL_INJECTION)
        
        await slow_print(f"\n--- VALIDATING PATCH {i} ---")
        await slow_print(f"ID: {patch.vulnerability_id}")
        await slow_print(f"Type: {vuln_type.value}")
        await slow_print(f"Original: {patch.original_code}")
        await slow_print(f"Patched:  {patch.patched_code}")
        await slow_print(f"Expected Confidence: {patch.confidence_score}")
        
        # Run comprehensive validation
        result = await validation_engine.validate_patch(patch, vuln_type)
        validation_results.append(result)
        
        await slow_print(f"\n📊 VALIDATION RESULTS:")
        await slow_print(f"  Status: {result.status.value.upper()}")
        await slow_print(f"  Confidence: {result.confidence_score:.2f}")
        await slow_print(f"  Execution Safe: {result.execution_safe}")
        await slow_print(f"  Performance Impact: {result.performance_impact}")
        
        # Syntax validation details
        await slow_print(f"\n  🔤 Syntax Validation:")
        await slow_print(f"    Valid: {result.syntax_validation.is_valid}")
        if result.syntax_validation.errors:
            await slow_print(f"    Errors: {result.syntax_validation.errors}")
        if result.syntax_validation.warnings:
            await slow_print(f"    Warnings: {result.syntax_validation.warnings}")
        
        # Security validation details
        await slow_print(f"\n  🛡️ Security Validation:")
        await slow_print(f"    Fixed: {result.security_validation.is_fixed}")
        await slow_print(f"    Security Score: {result.security_validation.security_score:.2f}")
        if result.security_validation.improvements:
            await slow_print(f"    Improvements: {len(result.security_validation.improvements)}")
        if result.security_validation.remaining_issues:
            await slow_print(f"    Remaining Issues: {len(result.security_validation.remaining_issues)}")
        
        # Test results
        if result.security_validation.test_results:
            passed_tests = sum(1 for test in result.security_validation.test_results if test.get('passed'))
            total_tests = len(result.security_validation.test_results)
            await slow_print(f"    Security Tests: {passed_tests}/{total_tests} passed")
        
        # Recommendations
        if result.recommendations:
            await slow_print(f"\n  💡 Recommendations:")
            for rec in result.recommendations[:3]:  # Show first 3
                await slow_print(f"    {rec}")
        
        # AI Analysis (if available)
        if result.ai_analysis:
            # Extract key parts of AI analysis
            if "SECURITY_ASSESSMENT:" in result.ai_analysis:
                assessment_match = re.search(r'SECURITY_ASSESSMENT:\s*(\w+)', result.ai_analysis)
                if assessment_match:
                    await slow_print(f"    AI Assessment: {assessment_match.group(1)}")
    
    # Generate summary statistics
    await slow_print(f"\n🎯 VALIDATION SUMMARY")
    await slow_print("=" * 60)
    
    total_patches = len(validation_results)
    passed_patches = len([r for r in validation_results if r.status == ValidationStatus.PASSED])
    failed_patches = len([r for r in validation_results if r.status == ValidationStatus.FAILED])
    warning_patches = len([r for r in validation_results if r.status == ValidationStatus.WARNING])
    manual_review_patches = len([r for r in validation_results if r.status == ValidationStatus.MANUAL_REVIEW])
    
    await slow_print(f"📊 Status Distribution:")
    await slow_print(f"  ✅ Passed: {passed_patches}/{total_patches} ({passed_patches/total_patches*100:.1f}%)")
    await slow_print(f"  ❌ Failed: {failed_patches}/{total_patches} ({failed_patches/total_patches*100:.1f}%)")
    await slow_print(f"  ⚠️  Warning: {warning_patches}/{total_patches} ({warning_patches/total_patches*100:.1f}%)")
    await slow_print(f"  🔍 Manual Review: {manual_review_patches}/{total_patches} ({manual_review_patches/total_patches*100:.1f}%)")
    
    # Confidence statistics
    confidence_scores = [r.confidence_score for r in validation_results]
    avg_confidence = sum(confidence_scores) / len(confidence_scores)
    high_confidence = len([c for c in confidence_scores if c >= 0.8])
    
    await slow_print(f"\n📈 Confidence Analysis:")
    await slow_print(f"  Average Confidence: {avg_confidence:.2f}")
    await slow_print(f"  High Confidence (≥0.8): {high_confidence}/{total_patches}")
    await slow_print(f"  Confidence Range: {min(confidence_scores):.2f} - {max(confidence_scores):.2f}")
    
    # Security effectiveness
    security_fixed = len([r for r in validation_results if r.security_validation.is_fixed])
    execution_safe = len([r for r in validation_results if r.execution_safe])
    
    await slow_print(f"\n🛡️ Security Effectiveness:")
    await slow_print(f"  Vulnerabilities Fixed: {security_fixed}/{total_patches} ({security_fixed/total_patches*100:.1f}%)")
    await slow_print(f"  Execution Safe: {execution_safe}/{total_patches} ({execution_safe/total_patches*100:.1f}%)")
    
    # Performance impact analysis
    performance_impacts = [r.performance_impact for r in validation_results]
    impact_counts = {impact: performance_impacts.count(impact) for impact in set(performance_impacts)}
    
    await slow_print(f"\n⚡ Performance Impact:")
    for impact, count in impact_counts.items():
        await slow_print(f"  {impact.capitalize()}: {count} patches")
    
    await slow_print(f"\n✨ Validation demo completed successfully!")
    await slow_print("=" * 60)

def generate_validation_report(results: List[ComprehensiveValidationResult]) -> str:
    """Generate a detailed validation report"""
    
    report = []
    report.append("# SECURITY PATCH VALIDATION REPORT")
    report.append("=" * 50)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total Patches Validated: {len(results)}")
    report.append("")
    
    # Executive Summary
    report.append("## EXECUTIVE SUMMARY")
    report.append("-" * 30)
    
    status_counts = {}
    for status in ValidationStatus:
        count = len([r for r in results if r.status == status])
        status_counts[status.value] = count
    
    for status, count in status_counts.items():
        percentage = (count / len(results)) * 100 if results else 0
        report.append(f"{status.upper()}: {count} ({percentage:.1f}%)")
    
    report.append("")
    
    # Detailed Results
    report.append("## DETAILED VALIDATION RESULTS")
    report.append("-" * 35)
    
    for i, result in enumerate(results, 1):
        report.append(f"\n### Patch {i}: {result.patch_id}")
        report.append(f"Status: {result.status.value.upper()}")
        report.append(f"Confidence: {result.confidence_score:.2f}")
        report.append(f"Execution Safe: {result.execution_safe}")
        report.append(f"Security Fixed: {result.security_validation.is_fixed}")
        
        if result.recommendations:
            report.append("Recommendations:")
            for rec in result.recommendations:
                report.append(f"  - {rec}")
        
        report.append("")
    
    return "\n".join(report)

def setup_validation_instructions():
    """Display setup instructions for the validation agent"""
    print("\n🔍 VALIDATION AGENT SETUP:")
    print("=" * 40)
    print("1. Install optional AI validation:")
    print("   pip install ollama")
    print("2. Pull validation model:")
    print("   ollama pull deepseek-r1")
    print("3. Run validation demo:")
    print("   python3 validation-agent.py")
    print()
    print("🎯 FEATURES:")
    print("- Comprehensive syntax validation")
    print("- Multi-layered security testing") 
    print("- AI-enhanced validation analysis")
    print("- Pattern-based vulnerability detection")
    print("- Confidence scoring and recommendations")
    print("- Performance impact assessment")
    print("- Detailed validation reports")

if __name__ == "__main__":
    if not VALIDATION_OLLAMA_AVAILABLE:
        print("ℹ️ Running in rule-based validation mode")
        print("💡 Install ollama for enhanced AI validation")
    
    print("\n" + "="*60)
    print("🔍 SECURITY PATCH VALIDATION AGENT")
    print("="*60)
    
    asyncio.run(demo_comprehensive_validation())