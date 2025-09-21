import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import hashlib
import re
import os
import tempfile
from enum import Enum

try:
    import ollama
    PATCH_OLLAMA_AVAILABLE = True
    print("✅ Ollama package available for patch generation")
except ImportError:
    PATCH_OLLAMA_AVAILABLE = False
    print("❌ Ollama not installed for patch generation")

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

@dataclass
class VulnerableCodeSample:
    id: str
    name: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    language: str
    vulnerable_code: str
    description: str
    line_number: int
    file_path: str

@dataclass
class PatchResult:
    vulnerability_id: str
    original_code: str
    patched_code: str
    explanation: str
    confidence_score: float
    patch_type: str
    test_cases: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.now)

@dataclass
class ValidationResult:
    is_valid: bool
    syntax_errors: List[str] = field(default_factory=list)
    security_improvements: List[str] = field(default_factory=list)
    potential_issues: List[str] = field(default_factory=list)

class VulnerableCodeDataset:
    """Dataset of vulnerable code samples for testing patch generation"""
    
    def __init__(self):
        self.samples = self._create_vulnerable_samples()
    
    def _create_vulnerable_samples(self) -> List[VulnerableCodeSample]:
        """Create a comprehensive dataset of vulnerable code samples"""
        
        samples = []
        
        samples.extend([
            VulnerableCodeSample(
                id="sql_01",
                name="Basic SQL Injection - String Concatenation",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=SeverityLevel.CRITICAL,
                language="python",
                vulnerable_code='query = "SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + password + "\'"',
                description="SQL injection via string concatenation in login query",
                line_number=3,
                file_path="login.py"
            ),
            VulnerableCodeSample(
                id="sql_02", 
                name="SQL Injection - f-string",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=SeverityLevel.CRITICAL,
                language="python",
                vulnerable_code='cursor.execute(f"DELETE FROM posts WHERE id = {post_id} AND user_id = {user_id}")',
                description="SQL injection using f-string formatting",
                line_number=15,
                file_path="posts.py"
            ),
            VulnerableCodeSample(
                id="sql_03",
                name="SQL Injection - % formatting", 
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=SeverityLevel.CRITICAL,
                language="python",
                vulnerable_code='query = "UPDATE users SET email = \'%s\' WHERE id = %s" % (email, user_id)',
                description="SQL injection using % string formatting",
                line_number=8,
                file_path="users.py"
            )
        ])

        samples.extend([
            VulnerableCodeSample(
                id="xss_01",
                name="DOM-based XSS - innerHTML",
                vulnerability_type=VulnerabilityType.XSS,
                severity=SeverityLevel.HIGH,
                language="javascript",
                vulnerable_code='document.getElementById("content").innerHTML = userInput;',
                description="XSS via direct innerHTML assignment",
                line_number=12,
                file_path="display.js"
            ),
            VulnerableCodeSample(
                id="xss_02",
                name="XSS - document.write",
                vulnerability_type=VulnerabilityType.XSS,
                severity=SeverityLevel.HIGH,
                language="javascript", 
                vulnerable_code='document.write("<div>" + userComment + "</div>");',
                description="XSS via document.write with user input",
                line_number=25,
                file_path="comments.js"
            ),
            VulnerableCodeSample(
                id="xss_03",
                name="Server-side XSS - Template injection",
                vulnerability_type=VulnerabilityType.XSS,
                severity=SeverityLevel.HIGH,
                language="python",
                vulnerable_code='return f"<h1>Welcome {username}</h1>"',
                description="Server-side XSS via template string",
                line_number=7,
                file_path="welcome.py"
            )
        ])
        
        samples.extend([
            VulnerableCodeSample(
                id="cmd_01",
                name="Command Injection - os.system",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                severity=SeverityLevel.CRITICAL,
                language="python",
                vulnerable_code='os.system("ping -c 4 " + user_ip)',
                description="Command injection via os.system",
                line_number=18,
                file_path="network.py"
            ),
            VulnerableCodeSample(
                id="cmd_02",
                name="Command Injection - subprocess shell=True",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                severity=SeverityLevel.CRITICAL,
                language="python",
                vulnerable_code='subprocess.run(f"ls -la {directory}", shell=True)',
                description="Command injection via subprocess with shell=True",
                line_number=33,
                file_path="files.py"
            )
        ])
        
        samples.extend([
            VulnerableCodeSample(
                id="path_01",
                name="Path Traversal - Direct file access",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                severity=SeverityLevel.HIGH,
                language="python",
                vulnerable_code='with open("/uploads/" + filename, "r") as f: return f.read()',
                description="Path traversal via direct file path concatenation",
                line_number=22,
                file_path="upload.py"
            ),
            VulnerableCodeSample(
                id="path_02", 
                name="Path Traversal - User-controlled path",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                severity=SeverityLevel.HIGH,
                language="python",
                vulnerable_code='file_path = request.args.get("file"); content = open(file_path).read()',
                description="Path traversal via user-controlled file parameter",
                line_number=45,
                file_path="download.py"
            )
        ])
        
        samples.extend([
            VulnerableCodeSample(
                id="crypto_01",
                name="Weak Hashing - MD5",
                vulnerability_type=VulnerabilityType.INSECURE_CRYPTO,
                severity=SeverityLevel.MEDIUM,
                language="python",
                vulnerable_code='password_hash = hashlib.md5(password.encode()).hexdigest()',
                description="Weak cryptographic hash using MD5",
                line_number=11,
                file_path="auth.py"
            ),
            VulnerableCodeSample(
                id="crypto_02",
                name="Weak Hashing - SHA1", 
                vulnerability_type=VulnerabilityType.INSECURE_CRYPTO,
                severity=SeverityLevel.MEDIUM,
                language="python",
                vulnerable_code='token = hashlib.sha1(str(time.time()).encode()).hexdigest()',
                description="Weak cryptographic hash using SHA1",
                line_number=28,
                file_path="tokens.py"
            ),
            VulnerableCodeSample(
                id="crypto_03",
                name="Hardcoded Encryption Key",
                vulnerability_type=VulnerabilityType.INSECURE_CRYPTO,
                severity=SeverityLevel.HIGH,
                language="python",
                vulnerable_code='key = "hardcoded_secret_key_123"; encrypted = AES.encrypt(data, key)',
                description="Hardcoded encryption key in source code",
                line_number=5,
                file_path="encryption.py"
            )
        ])
        
        # 6. Authentication Bypass Samples
        samples.extend([
            VulnerableCodeSample(
                id="auth_01",
                name="Authentication Bypass - Weak comparison",
                vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                severity=SeverityLevel.CRITICAL,
                language="python",
                vulnerable_code='if user_password == stored_password: return True',
                description="Timing attack vulnerability in password comparison",
                line_number=19,
                file_path="login.py"
            ),
            VulnerableCodeSample(
                id="auth_02",
                name="JWT Secret Exposure", 
                vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                severity=SeverityLevel.CRITICAL,
                language="python",
                vulnerable_code='jwt_secret = "secret123"; token = jwt.encode(payload, jwt_secret)',
                description="Weak JWT secret key",
                line_number=14,
                file_path="jwt_auth.py"
            )
        ])
        
        return samples
    
    def get_samples_by_type(self, vuln_type: VulnerabilityType) -> List[VulnerableCodeSample]:
        """Get all samples of a specific vulnerability type"""
        return [s for s in self.samples if s.vulnerability_type == vuln_type]
    
    def get_samples_by_severity(self, severity: SeverityLevel) -> List[VulnerableCodeSample]:
        """Get all samples of a specific severity level"""
        return [s for s in self.samples if s.severity == severity]
    
    def get_all_samples(self) -> List[VulnerableCodeSample]:
        """Get all vulnerable code samples"""
        return self.samples

class PatchGenerator:
    
    def __init__(self, model_name: str = "deepseek-r1:latest"):
        self.model_name = model_name
        self.use_ollama = PATCH_OLLAMA_AVAILABLE
        self.dataset = VulnerableCodeDataset()
        
        if self.use_ollama:
            self._check_model_availability()
        else:
            logger.warning("Ollama not available, using fallback patch generation")
        
        self.patch_templates = self._init_patch_templates()
    
    def _check_model_availability(self):
        """Check if the specified Ollama model is available"""
        try:
            models_response = ollama.list()
            
            if hasattr(models_response, 'models') and isinstance(models_response.models, list):
                model_list = models_response.models
            elif isinstance(models_response, list):
                model_list = models_response
            else:
                logger.error("Unexpected response format from ollama.list()")
                self.use_ollama = False
                return

            available_models = []
            for model_obj in model_list:
                if hasattr(model_obj, 'model'):
                    available_models.append(model_obj.model)
            
            model_found = any(self.model_name in model_name_str for model_name_str in available_models)
            
            if model_found:
                logger.info(f"✅ Using Ollama model for patches: {self.model_name}")
            else:
                logger.warning(f"❌ Model '{self.model_name}' not found")
                logger.info(f"Available models: {available_models}")
                self.use_ollama = False
                
        except Exception as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            self.use_ollama = False
    
    def _init_patch_templates(self) -> Dict[VulnerabilityType, Dict]:
        """Initialize patch templates for fallback mode"""
        return {
            VulnerabilityType.SQL_INJECTION: {
                "fix": "Use parameterized queries with placeholders",
                "template": 'cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))'
            },
            VulnerabilityType.XSS: {
                "fix": "Escape user input before inserting into DOM",
                "template": "element.textContent = userInput  // or use proper escaping library"
            },
            VulnerabilityType.COMMAND_INJECTION: {
                "fix": "Use subprocess with shell=False and validate input",
                "template": "subprocess.run(['ping', '-c', '4', validated_ip], check=True)"
            },
            VulnerabilityType.PATH_TRAVERSAL: {
                "fix": "Validate and sanitize file paths",
                "template": "safe_path = os.path.join(base_dir, os.path.basename(filename))"
            },
            VulnerabilityType.INSECURE_CRYPTO: {
                "fix": "Use strong cryptographic algorithms",
                "template": "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
            },
            VulnerabilityType.AUTHENTICATION_BYPASS: {
                "fix": "Use secure comparison methods and strong secrets",
                "template": "if hmac.compare_digest(user_password, stored_password): return True"
            }
        }
    
    async def generate_patch(self, sample: VulnerableCodeSample) -> PatchResult:
        logger.info(f"🔧 Generating patch for {sample.name} ({sample.vulnerability_type.value})")
        
        if self.use_ollama:
            try:
                return await self._generate_patch_with_ollama(sample)
            except Exception as e:
                logger.error(f"Ollama patch generation failed: {e}")
                return self._generate_fallback_patch(sample)
        else:
            return self._generate_fallback_patch(sample)
    
    async def _generate_patch_with_ollama(self, sample: VulnerableCodeSample) -> PatchResult:
        
        prompt = self._create_patch_prompt(sample)
        
        logger.info(f"🤖 Requesting patch from Ollama model: {self.model_name}")
        
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.1,
                    "top_k": 10,
                    "top_p": 0.9
                }
            )
            
            response_text = response['message']['content']
            logger.info("📝 Received patch response from Ollama")
            
            print("\n" + "="*60)
            print(f"🔧 PATCH RESPONSE FOR {sample.id}")
            print("="*60)
            print(response_text)
            print("="*60 + "\n")
            
            return await self._parse_patch_response(response_text, sample)
            
        except Exception as e:
            logger.error(f"Ollama API error during patch generation: {e}")
            raise
    
    def _create_patch_prompt(self, sample: VulnerableCodeSample) -> str:
        """Create a detailed prompt for patch generation"""
        
        prompt = f"""You are a cybersecurity expert who fixes code vulnerabilities.

**VULNERABILITY DETAILS:**
- ID: {sample.id}
- Type: {sample.vulnerability_type.value}
- Severity: {sample.severity.name}
- Language: {sample.language}
- Description: {sample.description}
- File: {sample.file_path}
- Line: {sample.line_number}

**VULNERABLE CODE:**
```{sample.language}
{sample.vulnerable_code}
```

**TASK**: Generate a secure fix for this vulnerability.

**RESPONSE FORMAT** (JSON only, no markdown):
{{
  "patched_code": "SECURE_CODE_HERE",
  "explanation": "Detailed explanation of the fix and why it's secure",
  "confidence": 0.95,
  "patch_type": "parameterized_query|input_validation|sanitization|encryption_upgrade|access_control|secure_comparison",
  "test_cases": [
    "test_case_1_description",
    "test_case_2_description"
  ]
}}

**SECURITY REQUIREMENTS BY TYPE:**

**SQL Injection**: Use parameterized queries, prepared statements, or ORM methods
**XSS**: Escape/encode output, use textContent instead of innerHTML, validate input  
**Command Injection**: Use subprocess with shell=False, validate/whitelist commands, avoid os.system
**Path Traversal**: Validate paths, use os.path.join with basename, check for ../
**Insecure Crypto**: Use bcrypt/scrypt for passwords, SHA-256+ for hashing, secure random for salts/keys
**Auth Bypass**: Use hmac.compare_digest(), implement proper session management, use strong secrets

**CRITICAL RULES:**
- Maintain the same functionality while fixing the security issue
- Include proper error handling where needed
- Add input validation if missing
- Use language-appropriate security libraries
- Include 2-3 relevant test cases that verify the fix

**OUTPUT MUST BE PURE JSON. NO MARKDOWN. NO EXPLANATIONS OUTSIDE JSON.**
"""
        
        return prompt
    
    async def _parse_patch_response(self, response_text: str, sample: VulnerableCodeSample) -> PatchResult:
        """Parse Ollama patch response and create PatchResult"""
        
        try:
            json_text = None
            
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
            if json_match:
                json_text = json_match.group(1)
            else:
                json_match = re.search(r'(\{[^}]*"patched_code"[^}]*\})', response_text, re.DOTALL)
                if json_match:
                    json_text = json_match.group(1)
                else:
                    json_match = re.search(r'(\{.*?\})', response_text, re.DOTALL)
                    if json_match:
                        json_text = json_match.group(1)
            
            if not json_text:
                logger.warning("No JSON found in patch response")
                return self._generate_fallback_patch(sample)
            
            patch_data = json.loads(json_text)
            
            return PatchResult(
                vulnerability_id=sample.id,
                original_code=sample.vulnerable_code,
                patched_code=patch_data.get('patched_code', ''),
                explanation=patch_data.get('explanation', 'AI-generated security patch'),
                confidence_score=patch_data.get('confidence', 0.8),
                patch_type=patch_data.get('patch_type', 'unknown'),
                test_cases=patch_data.get('test_cases', []),
                generated_at=datetime.now()
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed for patch: {e}")
            return self._generate_fallback_patch(sample)
        except Exception as e:
            logger.error(f"Unexpected error parsing patch: {e}")
            return self._generate_fallback_patch(sample)
    
    def _generate_fallback_patch(self, sample: VulnerableCodeSample) -> PatchResult:
        """Generate patch using predefined templates"""
        logger.info("🔄 Using fallback patch generation")
        
        template = self.patch_templates.get(sample.vulnerability_type)
        if not template:
            return PatchResult(
                vulnerability_id=sample.id,
                original_code=sample.vulnerable_code,
                patched_code=sample.vulnerable_code + "  # TODO: Fix security vulnerability",
                explanation=f"No automatic fix available for {sample.vulnerability_type.value}. Manual review required.",
                confidence_score=0.3,
                patch_type="manual_review_required"
            )
        
        return PatchResult(
            vulnerability_id=sample.id,
            original_code=sample.vulnerable_code,
            patched_code=template["template"],
            explanation=f"{template['fix']}. This is a template-based fix.",
            confidence_score=0.6,
            patch_type="template_based",
            test_cases=[f"Test that {sample.vulnerability_type.value} is prevented"]
        )
    
    def validate_patch(self, patch: PatchResult) -> ValidationResult:
        """Validate a generated patch for syntax and basic security"""
        
        validation = ValidationResult(is_valid=True)
        
        # Basic syntax check (for Python)
        if 'python' in patch.vulnerability_id.lower():
            try:
                compile(patch.patched_code, '<patch>', 'eval')
            except SyntaxError as e:
                validation.is_valid = False
                validation.syntax_errors.append(f"Syntax error: {e}")
        
        # Security improvement checks
        original_lower = patch.original_code.lower()
        patched_lower = patch.patched_code.lower()
        
        security_checks = [
            ("parameterized query", ["?", "%s", "execute("], "parameterized_query"),
            ("input escaping", ["escape", "sanitize", "textcontent"], "input_escaping"), 
            ("subprocess security", ["shell=false", "subprocess.run"], "subprocess_security"),
            ("path validation", ["os.path.join", "basename", "realpath"], "path_validation"),
            ("strong crypto", ["bcrypt", "scrypt", "pbkdf2", "sha256"], "strong_crypto"),
            ("secure comparison", ["compare_digest", "hmac"], "secure_comparison")
        ]
        
        for improvement_name, indicators, check_type in security_checks:
            if any(indicator in patched_lower for indicator in indicators):
                validation.security_improvements.append(f"Added {improvement_name}")
        
        # Check for potential issues
        if len(patch.patched_code.strip()) < 10:
            validation.potential_issues.append("Patch seems too short")
        
        if patch.confidence_score < 0.5:
            validation.potential_issues.append("Low confidence patch")
        
        return validation

async def demo_patch_generation():
    """Comprehensive demonstration of the patch generation system"""
    
    print("🚀 STANDALONE PATCH GENERATION DEMO")
    print("=" * 60)
    
    patch_generator = PatchGenerator(model_name="deepseek-r1:latest")
    dataset = patch_generator.dataset
    
    print(f"📊 Loaded {len(dataset.get_all_samples())} vulnerable code samples")
    print("\n🎯 Sample breakdown by vulnerability type:")
    for vuln_type in VulnerabilityType:
        samples = dataset.get_samples_by_type(vuln_type)
        print(f"  • {vuln_type.value}: {len(samples)} samples")
    

    print(f"\n🔧 Generating patches...")
    

    demo_samples = []
    for vuln_type in VulnerabilityType:
        type_samples = dataset.get_samples_by_type(vuln_type)[:2]  # First 2 of each type
        demo_samples.extend(type_samples)
    
    patches = []
    for i, sample in enumerate(demo_samples[:8], 1):  # Limit to 8 for demo
        print(f"\n--- GENERATING PATCH {i}/{len(demo_samples[:8])} ---")
        print(f"Sample: {sample.name}")
        print(f"Type: {sample.vulnerability_type.value}")
        print(f"Vulnerable Code: {sample.vulnerable_code}")
        
        patch = await patch_generator.generate_patch(sample)
        patches.append(patch)
        
        print(f"✅ Generated patch with confidence: {patch.confidence_score:.2f}")
    
    print(f"\n🎉 PATCH GENERATION COMPLETE")
    print("=" * 60)
    
    total_patches = len(patches)
    high_confidence = len([p for p in patches if p.confidence_score >= 0.8])
    
    print(f"📈 STATISTICS:")
    print(f"  • Total patches generated: {total_patches}")
    print(f"  • High confidence patches (≥80%): {high_confidence}")
    print(f"  • Success rate: {(high_confidence/total_patches)*100:.1f}%")
    
    print(f"\n🔍 PATCH DETAILS:")
    for i, patch in enumerate(patches, 1):
        print(f"\n--- PATCH {i} ---")
        print(f"ID: {patch.vulnerability_id}")
        print(f"Type: {patch.patch_type}")
        print(f"Confidence: {patch.confidence_score:.2f}")
        print(f"Original: {patch.original_code}")
        print(f"Patched:  {patch.patched_code}")
        print(f"Explanation: {patch.explanation}")
        
        validation = patch_generator.validate_patch(patch)
        print(f"Valid: {validation.is_valid}")
        if validation.security_improvements:
            print(f"Security Improvements: {', '.join(validation.security_improvements)}")
        if validation.potential_issues:
            print(f"Potential Issues: {', '.join(validation.potential_issues)}")
    
    print(f"\n✨ Demo completed successfully!")

def setup_patch_instructions():
    print("\n🔧 STANDALONE PATCH GENERATION SETUP:")
    print("=" * 45)
    print("1. Install Ollama:")
    print("   pip install ollama")
    print("2. Pull a model:")
    print("   ollama pull deepseek-r1")
    print("3. Run the patch generation demo:")
    print("   python3 patch-generation-agent.py")
    print()
    print("🛡️  FEATURES:")
    print("- 15+ vulnerable code samples across 6 vulnerability types")
    print("- AI-powered secure code generation")
    print("- Template-based fallback fixes")
    print("- Comprehensive patch validation")
    print("- No external dependencies on detection agents")

if __name__ == "__main__":
    if not PATCH_OLLAMA_AVAILABLE:
        print("❌ Ollama package not found!")
        setup_patch_instructions()
    else:
        asyncio.run(demo_patch_generation())
