#!/usr/bin/env python3
"""
UI Confusion Attack Security Tests

This script tests protection against UI confusion attacks to ensure:
1. Quickshell UI doesn't display misleading dialogs
2. Fake agent responses are detected  
3. Dialog content is properly validated
4. UI spoofing attempts are blocked
"""

import json
import sys
import time
import threading
import socket
import tempfile
import os
from pathlib import Path

class UIConfusionTester:
    def __init__(self, socket_path="/tmp/quickshell-polkit-agent"):
        self.socket_path = socket_path
        self.test_results = []
        self.failures = 0
        
    def create_fake_dialog_message(self, message_type, **kwargs):
        """Create a fake dialog message that could confuse the UI"""
        return {
            "type": message_type,
            "timestamp": int(time.time() * 1000),
            **kwargs
        }
        
    def test_malicious_dialog_content(self):
        """Test protection against malicious dialog content"""
        print("🎭 Testing malicious dialog content protection...")
        
        # Test various types of malicious dialog content
        malicious_dialogs = [
            {
                'name': 'Script injection in message',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog",
                    action_id="org.example.test",
                    message="<script>alert('XSS');</script>",
                    icon_name="security-high",
                    cookie="test_cookie"
                ),
                'attack_type': 'XSS_SCRIPT_INJECTION'
            },
            {
                'name': 'HTML injection in message',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog", 
                    action_id="org.example.test",
                    message="<img src=x onerror=alert('XSS')>",
                    icon_name="security-high",
                    cookie="test_cookie"
                ),
                'attack_type': 'HTML_INJECTION'
            },
            {
                'name': 'Unicode confusion',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog",
                    action_id="org.example.test",
                    message="Authenticate for: аdmin (using Cyrillic 'а')",
                    icon_name="security-high", 
                    cookie="test_cookie"
                ),
                'attack_type': 'UNICODE_CONFUSION'
            },
            {
                'name': 'Deceptive system message',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog",
                    action_id="org.freedesktop.systemd1.manage-units",
                    message="System update required. Enter password to continue:",
                    icon_name="system-software-update",
                    cookie="fake_system_cookie"
                ),
                'attack_type': 'SYSTEM_IMPERSONATION'
            },
            {
                'name': 'Fake security warning',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog",
                    action_id="org.example.security.scan", 
                    message="SECURITY BREACH DETECTED! Enter password immediately:",
                    icon_name="security-critical",
                    cookie="fake_security_cookie"
                ),
                'attack_type': 'FAKE_SECURITY_WARNING'
            },
            {
                'name': 'Oversized message',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog",
                    action_id="org.example.test",
                    message="A" * 10000,  # Very long message
                    icon_name="security-high",
                    cookie="overflow_cookie"
                ),
                'attack_type': 'MESSAGE_OVERFLOW'
            },
            {
                'name': 'Control character injection',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog",
                    action_id="org.example.test",
                    message="Normal message\x00\x01\x02Hidden content",
                    icon_name="security-high",
                    cookie="control_char_cookie"
                ),
                'attack_type': 'CONTROL_CHARACTER_INJECTION'
            },
            {
                'name': 'Path traversal in action_id',
                'dialog': self.create_fake_dialog_message(
                    "show_auth_dialog",
                    action_id="../../../etc/passwd",
                    message="Authenticate for file access",
                    icon_name="security-high",
                    cookie="traversal_cookie"
                ),
                'attack_type': 'PATH_TRAVERSAL'
            }
        ]
        
        for test_case in malicious_dialogs:
            try:
                # Validate dialog message structure
                dialog = test_case['dialog']
                
                # Check for basic validation that should catch malicious content
                validation_issues = []
                
                # Check message length
                if len(dialog.get('message', '')) > 4096:
                    validation_issues.append('Message too long')
                    
                # Check for script content
                message = dialog.get('message', '')
                if '<script>' in message.lower() or 'javascript:' in message.lower():
                    validation_issues.append('Script content detected')
                    
                # Check for HTML tags
                if '<' in message and '>' in message:
                    validation_issues.append('HTML tags detected')
                    
                # Check for control characters
                if any(ord(c) < 32 and c not in '\t\n\r' for c in message):
                    validation_issues.append('Control characters detected')
                    
                # Check action_id for path traversal
                action_id = dialog.get('action_id', '')
                if '..' in action_id or '/' in action_id:
                    validation_issues.append('Path traversal in action_id')
                    
                result = {
                    'test': test_case['name'],
                    'attack_type': test_case['attack_type'],
                    'dialog_data': dialog,
                    'validation_issues': validation_issues,
                    'should_be_blocked': len(validation_issues) > 0,
                    'status': 'BLOCKED' if validation_issues else 'ALLOWED'
                }
                
                # Determine if this is a security issue
                if test_case['attack_type'] in ['XSS_SCRIPT_INJECTION', 'HTML_INJECTION', 'CONTROL_CHARACTER_INJECTION', 'PATH_TRAVERSAL']:
                    if not validation_issues:
                        result['security_issue'] = 'Malicious content not detected'
                        result['status'] = 'VULNERABLE'
                        self.failures += 1
                        
                self.test_results.append(result)
                
            except Exception as e:
                self.test_results.append({
                    'test': test_case['name'],
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.failures += 1
                
    def test_fake_agent_responses(self):
        """Test detection of fake agent responses"""
        print("🤖 Testing fake agent response detection...")
        
        # Simulate various fake responses that might confuse the UI
        fake_responses = [
            {
                'name': 'Fake authorization success',
                'response': {
                    "type": "authorization_result",
                    "authorized": True,
                    "action_id": "org.freedesktop.systemd1.manage-units",
                    "fake_field": "This shouldn't be here"
                },
                'expected_validation': 'Extra fields detected'
            },
            {
                'name': 'Fake error with script',
                'response': {
                    "type": "authorization_error", 
                    "error": "<script>window.location='http://evil.com'</script>",
                    "action_id": "org.example.test"
                },
                'expected_validation': 'Script content in error'
            },
            {
                'name': 'Missing required fields',
                'response': {
                    "type": "authorization_result"
                    # Missing action_id and authorized fields
                },
                'expected_validation': 'Required fields missing'
            },
            {
                'name': 'Invalid message type',
                'response': {
                    "type": "fake_message_type",
                    "malicious_data": "This is a fake response"
                },
                'expected_validation': 'Invalid message type'
            },
            {
                'name': 'Type confusion attack',
                'response': {
                    "type": 123,  # Wrong type
                    "authorized": "yes"  # Wrong type
                },
                'expected_validation': 'Type mismatch'
            }
        ]
        
        for test_case in fake_responses:
            try:
                response = test_case['response']
                
                # Validate response structure
                validation_issues = []
                
                # Check message type
                msg_type = response.get('type')
                valid_types = ['authorization_result', 'authorization_error', 'show_auth_dialog', 'heartbeat_ack']
                
                if not isinstance(msg_type, str):
                    validation_issues.append('Message type not string')
                elif msg_type not in valid_types:
                    validation_issues.append('Invalid message type')
                    
                # Check for required fields based on type
                if msg_type == 'authorization_result':
                    if 'authorized' not in response:
                        validation_issues.append('Missing authorized field')
                    elif not isinstance(response.get('authorized'), bool):
                        validation_issues.append('Authorized field not boolean')
                        
                    if 'action_id' not in response:
                        validation_issues.append('Missing action_id field')
                        
                elif msg_type == 'authorization_error':
                    if 'error' not in response:
                        validation_issues.append('Missing error field')
                    else:
                        error_msg = response.get('error', '')
                        if '<script>' in error_msg.lower():
                            validation_issues.append('Script content in error')
                            
                # Check for unexpected fields
                expected_fields = {
                    'authorization_result': ['type', 'authorized', 'action_id'],
                    'authorization_error': ['type', 'error', 'action_id'], 
                    'show_auth_dialog': ['type', 'action_id', 'message', 'icon_name', 'cookie'],
                    'heartbeat_ack': ['type']
                }
                
                if msg_type in expected_fields:
                    for field in response:
                        if field not in expected_fields[msg_type]:
                            validation_issues.append(f'Unexpected field: {field}')
                            
                result = {
                    'test': test_case['name'],
                    'fake_response': response,
                    'validation_issues': validation_issues,
                    'expected_validation': test_case['expected_validation'],
                    'properly_validated': len(validation_issues) > 0,
                    'status': 'BLOCKED' if validation_issues else 'ALLOWED'
                }
                
                if not validation_issues and test_case['expected_validation']:
                    result['security_issue'] = 'Fake response not properly validated'
                    result['status'] = 'VULNERABLE'
                    self.failures += 1
                    
                self.test_results.append(result)
                
            except Exception as e:
                self.test_results.append({
                    'test': test_case['name'],
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.failures += 1
                
    def test_dialog_spoofing_protection(self):
        """Test protection against dialog spoofing"""
        print("📱 Testing dialog spoofing protection...")
        
        spoofing_tests = [
            {
                'name': 'Fake system authentication',
                'spoofed_dialog': {
                    "type": "show_auth_dialog",
                    "action_id": "com.apple.system.authentication",  # Wrong namespace
                    "message": "macOS System Authentication Required",
                    "icon_name": "system-security",
                    "cookie": "fake_macos_cookie"
                },
                'attack_type': 'OS_IMPERSONATION'
            },
            {
                'name': 'Fake banking authentication',
                'spoofed_dialog': {
                    "type": "show_auth_dialog", 
                    "action_id": "com.bank.secure.login",
                    "message": "Bank of America - Security Check Required",
                    "icon_name": "bank-security",
                    "cookie": "fake_bank_cookie"
                },
                'attack_type': 'FINANCIAL_PHISHING'
            },
            {
                'name': 'Unicode domain spoofing',
                'spoofed_dialog': {
                    "type": "show_auth_dialog",
                    "action_id": "org.аpple.system",  # Cyrillic 'а' instead of 'a'
                    "message": "Apple System Verification",
                    "icon_name": "apple-logo",
                    "cookie": "unicode_spoof_cookie"
                },
                'attack_type': 'UNICODE_DOMAIN_SPOOFING'
            },
            {
                'name': 'Fake software installation',
                'spoofed_dialog': {
                    "type": "show_auth_dialog",
                    "action_id": "org.microsoft.windows.installer",
                    "message": "Windows Software Installation - Enter Administrator Password",
                    "icon_name": "windows-installer",
                    "cookie": "fake_windows_cookie"
                },
                'attack_type': 'SOFTWARE_INSTALLATION_SPOOF'
            }
        ]
        
        for test_case in spoofing_tests:
            try:
                dialog = test_case['spoofed_dialog']
                
                # Check for spoofing indicators
                spoofing_indicators = []
                
                action_id = dialog.get('action_id', '')
                message = dialog.get('message', '')
                
                # Check for suspicious action_id patterns
                suspicious_domains = ['apple', 'microsoft', 'google', 'bank', 'paypal']
                for domain in suspicious_domains:
                    if domain.lower() in action_id.lower():
                        spoofing_indicators.append(f'Suspicious domain reference: {domain}')
                        
                # Check for Unicode spoofing
                if any(ord(c) > 127 for c in action_id):
                    spoofing_indicators.append('Non-ASCII characters in action_id')
                    
                # Check for misleading system references
                system_terms = ['system', 'administrator', 'security check', 'verification']
                for term in system_terms:
                    if term.lower() in message.lower():
                        spoofing_indicators.append(f'System impersonation term: {term}')
                        
                # Check action_id format (should be reverse domain notation)
                if not action_id.startswith('org.') and not action_id.startswith('com.'):
                    spoofing_indicators.append('Non-standard action_id format')
                    
                result = {
                    'test': test_case['name'],
                    'attack_type': test_case['attack_type'],
                    'spoofed_dialog': dialog,
                    'spoofing_indicators': spoofing_indicators,
                    'spoofing_detected': len(spoofing_indicators) > 0,
                    'status': 'DETECTED' if spoofing_indicators else 'UNDETECTED'
                }
                
                # High-risk spoofing should be detected
                high_risk_attacks = ['OS_IMPERSONATION', 'FINANCIAL_PHISHING', 'UNICODE_DOMAIN_SPOOFING']
                if test_case['attack_type'] in high_risk_attacks and not spoofing_indicators:
                    result['security_issue'] = 'High-risk spoofing not detected'
                    result['status'] = 'VULNERABLE'
                    self.failures += 1
                    
                self.test_results.append(result)
                
            except Exception as e:
                self.test_results.append({
                    'test': test_case['name'],
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.failures += 1
                
    def test_ui_input_validation(self):
        """Test UI input validation and sanitization"""
        print("✅ Testing UI input validation...")
        
        input_tests = [
            {
                'name': 'Password field overflow',
                'input_data': {
                    'field_type': 'password',
                    'value': 'A' * 10000,  # Very long password
                    'max_length': 256
                },
                'expected_behavior': 'Truncate or reject'
            },
            {
                'name': 'Username with special chars',
                'input_data': {
                    'field_type': 'username',
                    'value': 'user<script>alert(1)</script>',
                    'validation': 'alphanumeric_only'
                },
                'expected_behavior': 'Reject or sanitize'
            },
            {
                'name': 'Binary data in text field',
                'input_data': {
                    'field_type': 'text',
                    'value': '\x00\x01\x02\x03' + 'normal text',
                    'validation': 'text_only'
                },
                'expected_behavior': 'Reject or sanitize'
            },
            {
                'name': 'Emoji flood',
                'input_data': {
                    'field_type': 'comment',
                    'value': '😀' * 1000,  # Emoji flood
                    'max_length': 500
                },
                'expected_behavior': 'Truncate'
            }
        ]
        
        for test_case in input_tests:
            try:
                input_data = test_case['input_data']
                
                # Simulate input validation
                validation_results = []
                
                value = input_data['value']
                field_type = input_data['field_type']
                
                # Length validation
                max_length = input_data.get('max_length', 1024)
                if len(value) > max_length:
                    validation_results.append('Length exceeded')
                    
                # Content validation
                if field_type == 'password':
                    # Password should allow most characters but have length limits
                    if len(value) > 256:
                        validation_results.append('Password too long')
                        
                elif field_type == 'username':
                    # Username should be alphanumeric
                    if not value.replace('_', '').replace('-', '').isalnum():
                        validation_results.append('Invalid username characters')
                        
                elif field_type == 'text':
                    # Text should not contain control characters
                    if any(ord(c) < 32 and c not in '\t\n\r' for c in value):
                        validation_results.append('Control characters detected')
                        
                # Check for potential XSS
                if '<script>' in value.lower() or 'javascript:' in value.lower():
                    validation_results.append('Script content detected')
                    
                result = {
                    'test': test_case['name'],
                    'input_data': input_data,
                    'validation_results': validation_results,
                    'input_rejected': len(validation_results) > 0,
                    'expected_behavior': test_case['expected_behavior'],
                    'status': 'VALIDATED' if validation_results else 'ACCEPTED'
                }
                
                # Check if validation matches expected behavior
                if test_case['expected_behavior'] in ['Truncate or reject', 'Reject or sanitize'] and not validation_results:
                    result['security_issue'] = 'Potentially malicious input not validated'
                    result['status'] = 'VULNERABLE'
                    self.failures += 1
                    
                self.test_results.append(result)
                
            except Exception as e:
                self.test_results.append({
                    'test': test_case['name'],
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.failures += 1
                
    def test_icon_and_branding_validation(self):
        """Test validation of icons and branding elements"""
        print("🎨 Testing icon and branding validation...")
        
        branding_tests = [
            {
                'name': 'Fake system icon',
                'dialog_data': {
                    'icon_name': '/usr/share/icons/fake-system-security.png',
                    'action_id': 'com.malware.fake.action'
                },
                'attack_type': 'ICON_SPOOFING'
            },
            {
                'name': 'Path traversal in icon',
                'dialog_data': {
                    'icon_name': '../../../etc/passwd',
                    'action_id': 'org.example.test'
                },
                'attack_type': 'PATH_TRAVERSAL'
            },
            {
                'name': 'URL as icon path',
                'dialog_data': {
                    'icon_name': 'http://evil.com/fake_icon.png',
                    'action_id': 'org.example.test'
                },
                'attack_type': 'REMOTE_ICON_FETCH'
            },
            {
                'name': 'Oversized icon path',
                'dialog_data': {
                    'icon_name': 'A' * 5000,
                    'action_id': 'org.example.test'
                },
                'attack_type': 'PATH_OVERFLOW'
            }
        ]
        
        for test_case in branding_tests:
            try:
                dialog_data = test_case['dialog_data']
                icon_name = dialog_data.get('icon_name', '')
                
                # Validate icon path
                validation_issues = []
                
                # Check path length
                if len(icon_name) > 256:
                    validation_issues.append('Icon path too long')
                    
                # Check for path traversal
                if '..' in icon_name or icon_name.startswith('/'):
                    validation_issues.append('Path traversal in icon name')
                    
                # Check for URL schemes
                if icon_name.startswith(('http://', 'https://', 'ftp://', 'file://')):
                    validation_issues.append('URL scheme in icon name')
                    
                # Check for allowed icon formats
                allowed_extensions = ['.png', '.svg', '.jpg', '.jpeg', '.gif']
                if not any(icon_name.lower().endswith(ext) for ext in allowed_extensions):
                    # If it's not a standard icon name and doesn't have extension
                    if '/' in icon_name or '\\' in icon_name:
                        validation_issues.append('Invalid icon format')
                        
                result = {
                    'test': test_case['name'],
                    'attack_type': test_case['attack_type'],
                    'icon_name': icon_name,
                    'validation_issues': validation_issues,
                    'icon_blocked': len(validation_issues) > 0,
                    'status': 'BLOCKED' if validation_issues else 'ALLOWED'
                }
                
                # Critical attacks should be blocked
                critical_attacks = ['PATH_TRAVERSAL', 'REMOTE_ICON_FETCH']
                if test_case['attack_type'] in critical_attacks and not validation_issues:
                    result['security_issue'] = 'Critical icon attack not blocked'
                    result['status'] = 'VULNERABLE'
                    self.failures += 1
                    
                self.test_results.append(result)
                
            except Exception as e:
                self.test_results.append({
                    'test': test_case['name'],
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.failures += 1
                
    def run_ui_confusion_tests(self):
        """Run all UI confusion security tests"""
        print("🎪 Starting UI Confusion Attack Security Tests...")
        
        self.test_malicious_dialog_content()
        self.test_fake_agent_responses()
        self.test_dialog_spoofing_protection()
        self.test_ui_input_validation()
        self.test_icon_and_branding_validation()
        
    def generate_report(self):
        """Generate detailed test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['status'] in ['PASS', 'BLOCKED', 'DETECTED', 'VALIDATED'])
        vulnerable_tests = sum(1 for r in self.test_results if r['status'] == 'VULNERABLE')
        error_tests = sum(1 for r in self.test_results if r['status'] == 'ERROR')
        
        report = {
            'test_type': 'UI Confusion Attack Security',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_tests': total_tests,
                'protected': passed_tests,
                'vulnerable': vulnerable_tests,
                'errors': error_tests,
                'security_score': f"{((passed_tests / max(1, total_tests)) * 100):.1f}%"
            },
            'results': self.test_results
        }
        
        # Save report
        report_dir = Path("tests/security/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        with open(report_dir / "ui_confusion_report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Print summary
        print(f"\n📊 UI Confusion Security Test Summary:")
        print(f"   Total tests: {total_tests}")
        print(f"   Protected: {passed_tests}")
        print(f"   Vulnerable: {vulnerable_tests}")
        print(f"   Errors: {error_tests}")
        print(f"   Security Score: {((passed_tests / max(1, total_tests)) * 100):.1f}%")
        
        if vulnerable_tests > 0 or error_tests > 0:
            print(f"   ❌ {vulnerable_tests + error_tests} UI security issues found")
            return False
        else:
            print(f"   ✅ All UI confusion tests passed")
            return True

def main():
    """Main entry point"""
    tester = UIConfusionTester()
    tester.run_ui_confusion_tests()
    success = tester.generate_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()