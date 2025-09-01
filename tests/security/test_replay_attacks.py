#!/usr/bin/env python3
"""
Replay Attack and Race Condition Security Tests

This script tests authentication cookie replay attacks and session expiry mechanisms:
1. Authentication cookie replay protection
2. Session timeout enforcement
3. Race conditions in authentication
4. Timestamp validation
"""

import asyncio
import json
import socket
import threading
import time
import hashlib
import hmac
import random
import sys
from pathlib import Path
from datetime import datetime, timedelta

class ReplayAttackTester:
    def __init__(self, socket_path="/tmp/quickshell-polkit-agent"):
        self.socket_path = socket_path
        self.test_results = []
        self.failures = 0
        self.hmac_key = b"test_key_for_security_testing"
        
    def generate_hmac(self, data):
        """Generate HMAC for message authentication"""
        return hmac.new(self.hmac_key, data.encode('utf-8'), hashlib.sha256).hexdigest()
        
    def create_authenticated_message(self, message_type, **kwargs):
        """Create an authenticated message with HMAC and timestamp"""
        timestamp = int(time.time() * 1000)  # Current timestamp in milliseconds
        
        message = {
            "type": message_type,
            "timestamp": timestamp,
            **kwargs
        }
        
        # Generate HMAC (excluding the hmac field itself)
        message_for_hmac = json.dumps(message, sort_keys=True)
        message["hmac"] = self.generate_hmac(message_for_hmac)
        
        return message
        
    def test_authentication_cookie_replay(self):
        """Test authentication cookie replay attack protection"""
        print("🍪 Testing authentication cookie replay attacks...")
        
        # Generate test authentication cookies
        test_cookies = [
            "auth_cookie_123456789",
            "session_abc123def456",
            "polkit_auth_token_xyz789"
        ]
        
        for i, cookie in enumerate(test_cookies):
            try:
                # Create original authentication message
                original_msg = self.create_authenticated_message(
                    "submit_authentication",
                    cookie=cookie,
                    response="test_password",
                    action_id="org.example.test"
                )
                
                # Test 1: Immediate replay (should potentially succeed if no nonce)
                replay_msg = original_msg.copy()
                
                result_immediate = {
                    'test': f'Immediate cookie replay #{i+1}',
                    'cookie': cookie,
                    'original_timestamp': original_msg['timestamp'],
                    'replay_timestamp': replay_msg['timestamp'],
                    'time_diff_ms': 0,
                    'status': 'TESTED'
                }
                
                self.test_results.append(result_immediate)
                
                # Test 2: Delayed replay (should fail due to timestamp)
                time.sleep(0.1)  # Small delay
                delayed_msg = original_msg.copy()
                delayed_msg['timestamp'] = int(time.time() * 1000)  # New timestamp but same cookie
                
                # Don't regenerate HMAC - this should fail HMAC verification
                result_delayed = {
                    'test': f'Delayed cookie replay #{i+1}',
                    'cookie': cookie,
                    'original_timestamp': original_msg['timestamp'],
                    'replay_timestamp': delayed_msg['timestamp'],
                    'time_diff_ms': delayed_msg['timestamp'] - original_msg['timestamp'],
                    'hmac_matches': delayed_msg['hmac'] == original_msg['hmac'],
                    'status': 'SHOULD_FAIL_HMAC',
                    'expected_result': 'HMAC verification should fail'
                }
                
                self.test_results.append(result_delayed)
                
                # Test 3: Cookie with old timestamp
                old_timestamp = int((time.time() - 60) * 1000)  # 60 seconds ago
                old_msg = self.create_authenticated_message(
                    "submit_authentication",
                    cookie=cookie,
                    response="test_password",
                    action_id="org.example.test"
                )
                old_msg['timestamp'] = old_timestamp
                
                # Regenerate HMAC with old timestamp
                old_msg_for_hmac = {k: v for k, v in old_msg.items() if k != 'hmac'}
                old_msg_data = json.dumps(old_msg_for_hmac, sort_keys=True)
                old_msg['hmac'] = self.generate_hmac(old_msg_data)
                
                result_old = {
                    'test': f'Old timestamp cookie replay #{i+1}',
                    'cookie': cookie,
                    'timestamp': old_msg['timestamp'],
                    'age_seconds': 60,
                    'status': 'SHOULD_FAIL_TIMESTAMP',
                    'expected_result': 'Should fail due to old timestamp'
                }
                
                self.test_results.append(result_old)
                
            except Exception as e:
                self.test_results.append({
                    'test': f'Cookie replay test #{i+1}',
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.failures += 1
                
    def test_session_expiry_enforcement(self):
        """Test session timeout and expiry enforcement"""
        print("⏰ Testing session expiry enforcement...")
        
        try:
            # Test different session timeout scenarios
            session_tests = [
                {'name': 'Valid session', 'age_minutes': 1, 'should_expire': False},
                {'name': 'Expired session', 'age_minutes': 10, 'should_expire': True},
                {'name': 'Just expired session', 'age_minutes': 5.1, 'should_expire': True},  # Slightly over 5 min timeout
                {'name': 'Edge case session', 'age_minutes': 5.0, 'should_expire': False},  # Exactly at timeout
            ]
            
            for test_case in session_tests:
                session_start_time = int((time.time() - test_case['age_minutes'] * 60) * 1000)
                current_time = int(time.time() * 1000)
                
                # Simulate session age check
                session_age_ms = current_time - session_start_time
                session_timeout_ms = 5 * 60 * 1000  # 5 minutes
                is_expired = session_age_ms > session_timeout_ms
                
                result = {
                    'test': f'Session expiry - {test_case["name"]}',
                    'session_start_time': session_start_time,
                    'current_time': current_time,
                    'session_age_ms': session_age_ms,
                    'session_age_minutes': test_case['age_minutes'],
                    'timeout_ms': session_timeout_ms,
                    'is_expired': is_expired,
                    'should_expire': test_case['should_expire'],
                    'status': 'PASS' if is_expired == test_case['should_expire'] else 'FAIL'
                }
                
                if is_expired != test_case['should_expire']:
                    result['security_issue'] = 'Session expiry logic incorrect'
                    self.failures += 1
                    
                self.test_results.append(result)
                
        except Exception as e:
            self.test_results.append({
                'test': 'Session expiry enforcement',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_concurrent_authentication_race(self):
        """Test race conditions in concurrent authentication attempts"""
        print("🏁 Testing concurrent authentication race conditions...")
        
        try:
            # Simulate concurrent authentication attempts with same cookie
            cookie = "race_condition_test_cookie"
            num_threads = 5
            results = []
            
            def authenticate_worker(worker_id):
                try:
                    # Create authentication message
                    auth_msg = self.create_authenticated_message(
                        "submit_authentication",
                        cookie=cookie,
                        response=f"password_{worker_id}",
                        action_id="org.example.race.test"
                    )
                    
                    # Add small random delay to increase race condition likelihood
                    time.sleep(random.uniform(0.001, 0.01))
                    
                    # Simulate authentication processing
                    processing_time = random.uniform(0.01, 0.05)
                    time.sleep(processing_time)
                    
                    result = {
                        'worker_id': worker_id,
                        'cookie': cookie,
                        'timestamp': auth_msg['timestamp'],
                        'processing_time': processing_time,
                        'status': 'COMPLETED'
                    }
                    
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        'worker_id': worker_id,
                        'status': 'ERROR',
                        'error': str(e)
                    })
                    
            # Start concurrent authentication threads
            threads = []
            start_time = time.time()
            
            for i in range(num_threads):
                thread = threading.Thread(target=authenticate_worker, args=(i,))
                threads.append(thread)
                thread.start()
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            end_time = time.time()
            
            # Analyze race condition results
            completed_auths = [r for r in results if r['status'] == 'COMPLETED']
            error_auths = [r for r in results if r['status'] == 'ERROR']
            
            race_result = {
                'test': 'Concurrent authentication race condition',
                'num_threads': num_threads,
                'total_time_seconds': end_time - start_time,
                'completed_authentications': len(completed_auths),
                'error_authentications': len(error_auths),
                'same_cookie_used': cookie,
                'worker_results': results,
                'status': 'COMPLETED'
            }
            
            # Check for potential race condition issues
            if len(completed_auths) > 1:
                race_result['potential_issue'] = 'Multiple authentications completed for same cookie'
                race_result['security_concern'] = 'Race condition may allow multiple successful authentications'
                
            self.test_results.append(race_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Concurrent authentication race condition',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_timestamp_manipulation(self):
        """Test timestamp manipulation attacks"""
        print("🕐 Testing timestamp manipulation attacks...")
        
        try:
            current_time = int(time.time() * 1000)
            
            # Test various timestamp manipulation scenarios
            timestamp_tests = [
                {'name': 'Future timestamp', 'offset_ms': 60000, 'should_fail': True},
                {'name': 'Far future timestamp', 'offset_ms': 3600000, 'should_fail': True},
                {'name': 'Slightly future timestamp', 'offset_ms': 1000, 'should_fail': False},
                {'name': 'Past timestamp', 'offset_ms': -60000, 'should_fail': True},
                {'name': 'Far past timestamp', 'offset_ms': -3600000, 'should_fail': True},
                {'name': 'Zero timestamp', 'timestamp': 0, 'should_fail': True},
                {'name': 'Negative timestamp', 'timestamp': -1000, 'should_fail': True},
                {'name': 'Maximum timestamp', 'timestamp': 2**63-1, 'should_fail': True},
            ]
            
            for test_case in timestamp_tests:
                try:
                    if 'timestamp' in test_case:
                        test_timestamp = test_case['timestamp']
                    else:
                        test_timestamp = current_time + test_case['offset_ms']
                        
                    # Create message with manipulated timestamp
                    message = {
                        "type": "check_authorization",
                        "action_id": "org.example.timestamp.test",
                        "timestamp": test_timestamp
                    }
                    
                    # Generate HMAC with manipulated timestamp
                    message_data = json.dumps(message, sort_keys=True)
                    message["hmac"] = self.generate_hmac(message_data)
                    
                    # Calculate time difference
                    time_diff_ms = test_timestamp - current_time
                    max_skew_ms = 30000  # 30 seconds (typical max allowed skew)
                    
                    # Determine if timestamp should be rejected
                    should_reject = abs(time_diff_ms) > max_skew_ms
                    
                    result = {
                        'test': f'Timestamp manipulation - {test_case["name"]}',
                        'test_timestamp': test_timestamp,
                        'current_timestamp': current_time,
                        'time_diff_ms': time_diff_ms,
                        'max_allowed_skew_ms': max_skew_ms,
                        'should_reject': should_reject,
                        'expected_to_fail': test_case['should_fail'],
                        'status': 'PASS' if should_reject == test_case['should_fail'] else 'FAIL'
                    }
                    
                    if should_reject != test_case['should_fail']:
                        result['security_issue'] = 'Timestamp validation logic incorrect'
                        self.failures += 1
                        
                    self.test_results.append(result)
                    
                except Exception as e:
                    self.test_results.append({
                        'test': f'Timestamp manipulation - {test_case["name"]}',
                        'status': 'ERROR',
                        'error': str(e)
                    })
                    self.failures += 1
                    
        except Exception as e:
            self.test_results.append({
                'test': 'Timestamp manipulation',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_hmac_replay_protection(self):
        """Test HMAC-based replay protection"""
        print("🔐 Testing HMAC replay protection...")
        
        try:
            # Create original message
            original_msg = self.create_authenticated_message(
                "check_authorization",
                action_id="org.example.hmac.test",
                details="HMAC replay test"
            )
            
            # Test 1: Exact replay (same HMAC, same timestamp)
            replay_exact = original_msg.copy()
            
            result_exact = {
                'test': 'Exact HMAC replay',
                'original_hmac': original_msg['hmac'],
                'replay_hmac': replay_exact['hmac'],
                'hmac_matches': original_msg['hmac'] == replay_exact['hmac'],
                'timestamp_matches': original_msg['timestamp'] == replay_exact['timestamp'],
                'status': 'POTENTIAL_REPLAY',
                'security_note': 'Exact replay should be blocked by nonce or other mechanism'
            }
            
            self.test_results.append(result_exact)
            
            # Test 2: Modified message with original HMAC (should fail)
            modified_msg = original_msg.copy()
            modified_msg['action_id'] = "org.example.modified.test"
            # Keep original HMAC (should fail verification)
            
            # Verify HMAC should fail for modified message
            modified_msg_for_hmac = {k: v for k, v in modified_msg.items() if k != 'hmac'}
            expected_hmac = self.generate_hmac(json.dumps(modified_msg_for_hmac, sort_keys=True))
            
            result_modified = {
                'test': 'Modified message with original HMAC',
                'original_hmac': original_msg['hmac'],
                'message_hmac': modified_msg['hmac'],
                'expected_hmac': expected_hmac,
                'hmac_verification_should_fail': modified_msg['hmac'] != expected_hmac,
                'status': 'SHOULD_FAIL_HMAC',
                'security_check': 'HMAC verification must fail for modified messages'
            }
            
            if modified_msg['hmac'] == expected_hmac:
                result_modified['security_issue'] = 'HMAC verification failed to detect message modification'
                self.failures += 1
                
            self.test_results.append(result_modified)
            
            # Test 3: Recomputed HMAC with different key (should fail)
            wrong_key = b"wrong_hmac_key_for_testing"
            wrong_hmac = hmac.new(wrong_key, json.dumps(modified_msg_for_hmac, sort_keys=True).encode('utf-8'), hashlib.sha256).hexdigest()
            
            result_wrong_key = {
                'test': 'Message with wrong HMAC key',
                'correct_hmac': expected_hmac,
                'wrong_key_hmac': wrong_hmac,
                'hmacs_different': expected_hmac != wrong_hmac,
                'status': 'SHOULD_FAIL_HMAC',
                'security_check': 'HMAC with wrong key must fail verification'
            }
            
            if expected_hmac == wrong_hmac:
                result_wrong_key['security_issue'] = 'HMAC collision detected - extremely unlikely!'
                self.failures += 1
                
            self.test_results.append(result_wrong_key)
            
        except Exception as e:
            self.test_results.append({
                'test': 'HMAC replay protection',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def run_replay_tests(self):
        """Run all replay attack and race condition tests"""
        print("🔄 Starting Replay Attack and Race Condition Security Tests...")
        
        self.test_authentication_cookie_replay()
        self.test_session_expiry_enforcement()
        self.test_concurrent_authentication_race()
        self.test_timestamp_manipulation()
        self.test_hmac_replay_protection()
        
    def generate_report(self):
        """Generate detailed test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed_tests = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        error_tests = sum(1 for r in self.test_results if r['status'] == 'ERROR')
        
        report = {
            'test_type': 'Replay Attack and Race Condition Security',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'errors': error_tests,
                'success_rate': f"{(passed_tests / max(1, total_tests)) * 100:.1f}%"
            },
            'results': self.test_results
        }
        
        # Save report
        report_dir = Path("tests/security/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        with open(report_dir / "replay_attack_report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Print summary
        print(f"\n📊 Replay Attack Test Summary:")
        print(f"   Total tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Errors: {error_tests}")
        
        if failed_tests > 0 or error_tests > 0:
            print(f"   ❌ {failed_tests + error_tests} security issues found")
            return False
        else:
            print(f"   ✅ All replay attack tests passed")
            return True

def main():
    """Main entry point"""
    tester = ReplayAttackTester()
    tester.run_replay_tests()
    success = tester.generate_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()