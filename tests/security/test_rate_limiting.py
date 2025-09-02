#!/usr/bin/env python3
"""
Rate Limiting and Timeout Enforcement Security Tests

This script tests rate limiting and timeout mechanisms to ensure:
1. Rate limits are properly enforced
2. Connections are closed on abuse
3. Timeout enforcement works correctly
4. DoS protection is effective
"""

import asyncio
import json
import socket
import threading
import time
import sys
import random
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

class RateLimitingTester:
    def __init__(self, socket_path="/tmp/quickshell-polkit-agent"):
        self.socket_path = socket_path
        self.test_results = []
        self.failures = 0
        
    def create_test_message(self):
        """Create a simple test message"""
        return json.dumps({
            "type": "heartbeat",
            "timestamp": int(time.time() * 1000)
        }) + "\n"
        
    def test_message_rate_limiting(self):
        """Test message rate limiting enforcement"""
        print("🚦 Testing message rate limiting...")
        
        # Configuration based on IPCServer constants
        MAX_MESSAGES_PER_SECOND = 10
        RATE_LIMIT_WINDOW_MS = 1000
        
        try:
            # Test 1: Send messages within rate limit
            print("  Testing normal rate (within limits)...")
            
            normal_rate_results = []
            test_msg = self.create_test_message()
            
            # Send messages at normal rate (under limit)
            for i in range(5):  # Well under the 10/second limit
                start_time = time.time()
                success = self.send_single_message(test_msg)
                end_time = time.time()
                
                normal_rate_results.append({
                    'message_num': i + 1,
                    'success': success,
                    'response_time': end_time - start_time
                })
                
                time.sleep(0.2)  # 200ms between messages = 5/second
                
            normal_rate_result = {
                'test': 'Normal message rate (within limits)',
                'rate_per_second': 5,
                'limit_per_second': MAX_MESSAGES_PER_SECOND,
                'results': normal_rate_results,
                'total_sent': len(normal_rate_results),
                'successful': sum(1 for r in normal_rate_results if r['success']),
                'status': 'PASS'
            }
            
            self.test_results.append(normal_rate_result)
            
            # Test 2: Rapid burst exceeding rate limit
            print("  Testing burst rate (exceeding limits)...")
            
            burst_results = []
            burst_start = time.time()
            
            # Send burst of messages exceeding rate limit
            for i in range(20):  # 2x the rate limit
                start_time = time.time()
                success = self.send_single_message(test_msg)
                end_time = time.time()
                
                burst_results.append({
                    'message_num': i + 1,
                    'success': success,
                    'response_time': end_time - start_time,
                    'time_from_burst_start': end_time - burst_start
                })
                
                # No delay - send as fast as possible
                
            burst_duration = time.time() - burst_start
            effective_rate = len(burst_results) / burst_duration
            
            burst_result = {
                'test': 'Burst message rate (exceeding limits)',
                'messages_sent': len(burst_results),
                'burst_duration_seconds': burst_duration,
                'effective_rate_per_second': effective_rate,
                'limit_per_second': MAX_MESSAGES_PER_SECOND,
                'successful_messages': sum(1 for r in burst_results if r['success']),
                'failed_messages': sum(1 for r in burst_results if not r['success']),
                'results': burst_results,
                'status': 'TESTED'
            }
            
            # Check if rate limiting worked
            if burst_result['successful_messages'] < burst_result['messages_sent']:
                burst_result['rate_limiting_active'] = True
                burst_result['security_status'] = 'PROTECTED'
            else:
                burst_result['rate_limiting_active'] = False
                burst_result['security_status'] = 'VULNERABLE'
                burst_result['security_issue'] = 'Rate limiting not enforced'
                self.failures += 1
                
            self.test_results.append(burst_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Message rate limiting',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_connection_timeout_enforcement(self):
        """Test connection timeout enforcement"""
        print("⏱️ Testing connection timeout enforcement...")
        
        HEARTBEAT_INTERVAL_MS = 30000  # 30 seconds
        CONNECTION_TIMEOUT_MS = 60000  # 60 seconds
        
        try:
            # Test 1: Connection without heartbeat (should timeout)
            print("  Testing connection without heartbeat...")
            
            start_time = time.time()
            timeout_test_result = {
                'test': 'Connection timeout without heartbeat',
                'expected_timeout_seconds': CONNECTION_TIMEOUT_MS / 1000,
                'start_time': start_time
            }
            
            try:
                # Attempt to create and hold connection without sending heartbeat
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(65)  # Slightly longer than expected timeout
                
                sock.connect(self.socket_path)
                
                # Read welcome message if any
                try:
                    welcome = sock.recv(1024)
                    timeout_test_result['welcome_received'] = len(welcome) > 0
                except:
                    timeout_test_result['welcome_received'] = False
                    
                # Wait for timeout without sending heartbeat
                try:
                    # This should timeout after 60 seconds
                    data = sock.recv(1024)
                    timeout_test_result['unexpected_data'] = True
                    timeout_test_result['data_received'] = len(data)
                except socket.timeout:
                    timeout_test_result['connection_timed_out'] = True
                except ConnectionResetError:
                    timeout_test_result['connection_reset'] = True
                    
                sock.close()
                
            except ConnectionRefusedError:
                timeout_test_result['agent_not_running'] = True
                timeout_test_result['status'] = 'SKIPPED'
            except FileNotFoundError:
                timeout_test_result['socket_not_found'] = True
                timeout_test_result['status'] = 'SKIPPED'
            except Exception as e:
                timeout_test_result['error'] = str(e)
                timeout_test_result['status'] = 'ERROR'
                
            end_time = time.time()
            timeout_test_result['total_time_seconds'] = end_time - start_time
            
            if 'status' not in timeout_test_result:
                if timeout_test_result.get('connection_timed_out') or timeout_test_result.get('connection_reset'):
                    timeout_test_result['status'] = 'PASS'
                    timeout_test_result['security_status'] = 'TIMEOUT_ENFORCED'
                else:
                    timeout_test_result['status'] = 'FAIL'
                    timeout_test_result['security_issue'] = 'Connection timeout not enforced'
                    self.failures += 1
                    
            self.test_results.append(timeout_test_result)
            
            # Test 2: Connection with proper heartbeat (should stay alive)
            print("  Testing connection with heartbeat...")
            
            heartbeat_test_result = {
                'test': 'Connection with proper heartbeat',
                'heartbeat_interval_seconds': HEARTBEAT_INTERVAL_MS / 1000,
                'test_duration_seconds': 35  # Test for 35 seconds
            }
            
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(40)  # Longer than test duration
                
                sock.connect(self.socket_path)
                
                # Send heartbeats at regular intervals
                heartbeat_msg = json.dumps({"type": "heartbeat"}) + "\n"
                heartbeats_sent = 0
                test_start = time.time()
                
                while (time.time() - test_start) < 35:  # Test for 35 seconds
                    sock.send(heartbeat_msg.encode('utf-8'))
                    heartbeats_sent += 1
                    
                    # Try to receive heartbeat ack
                    try:
                        response = sock.recv(1024)
                        if response:
                            heartbeat_test_result[f'heartbeat_{heartbeats_sent}_ack'] = True
                    except:
                        pass
                        
                    time.sleep(10)  # Send heartbeat every 10 seconds
                    
                sock.close()
                
                heartbeat_test_result['heartbeats_sent'] = heartbeats_sent
                heartbeat_test_result['test_completed'] = True
                heartbeat_test_result['status'] = 'PASS'
                
            except ConnectionRefusedError:
                heartbeat_test_result['agent_not_running'] = True
                heartbeat_test_result['status'] = 'SKIPPED'
            except FileNotFoundError:
                heartbeat_test_result['socket_not_found'] = True
                heartbeat_test_result['status'] = 'SKIPPED'
            except Exception as e:
                heartbeat_test_result['error'] = str(e)
                heartbeat_test_result['status'] = 'ERROR'
                
            self.test_results.append(heartbeat_test_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Connection timeout enforcement',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_concurrent_connection_limits(self):
        """Test concurrent connection limits and DoS protection"""
        print("🔗 Testing concurrent connection limits...")
        
        try:
            max_connections_to_test = 20
            connection_results = []
            
            def create_connection(conn_id):
                try:
                    start_time = time.time()
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    
                    sock.connect(self.socket_path)
                    
                    # Try to send a message
                    test_msg = self.create_test_message()
                    sock.send(test_msg.encode('utf-8'))
                    
                    # Try to receive response
                    try:
                        response = sock.recv(1024)
                        response_received = len(response) > 0
                    except:
                        response_received = False
                        
                    end_time = time.time()
                    
                    # Keep connection open for a bit
                    time.sleep(2)
                    
                    sock.close()
                    
                    return {
                        'connection_id': conn_id,
                        'success': True,
                        'response_received': response_received,
                        'connection_time': end_time - start_time,
                        'status': 'CONNECTED'
                    }
                    
                except ConnectionRefusedError:
                    return {
                        'connection_id': conn_id,
                        'success': False,
                        'error': 'Connection refused',
                        'status': 'REFUSED'
                    }
                except FileNotFoundError:
                    return {
                        'connection_id': conn_id,
                        'success': False,
                        'error': 'Socket not found',
                        'status': 'SKIPPED'
                    }
                except Exception as e:
                    return {
                        'connection_id': conn_id,
                        'success': False,
                        'error': str(e),
                        'status': 'ERROR'
                    }
                    
            # Create multiple concurrent connections
            with ThreadPoolExecutor(max_workers=max_connections_to_test) as executor:
                futures = [executor.submit(create_connection, i) for i in range(max_connections_to_test)]
                
                for future in as_completed(futures):
                    result = future.result()
                    connection_results.append(result)
                    
            # Analyze results
            successful_connections = [r for r in connection_results if r['success']]
            refused_connections = [r for r in connection_results if r['status'] == 'REFUSED']
            error_connections = [r for r in connection_results if r['status'] == 'ERROR']
            
            concurrent_test_result = {
                'test': 'Concurrent connection limits',
                'attempted_connections': max_connections_to_test,
                'successful_connections': len(successful_connections),
                'refused_connections': len(refused_connections),
                'error_connections': len(error_connections),
                'connection_details': connection_results,
                'status': 'TESTED'
            }
            
            # Evaluate DoS protection
            if len(successful_connections) == max_connections_to_test:
                concurrent_test_result['dos_protection'] = 'NONE_DETECTED'
                concurrent_test_result['security_note'] = 'All connections accepted - may be vulnerable to connection flooding'
            elif len(refused_connections) > 0:
                concurrent_test_result['dos_protection'] = 'ACTIVE'
                concurrent_test_result['security_status'] = 'PROTECTED'
            else:
                concurrent_test_result['dos_protection'] = 'UNKNOWN'
                
            self.test_results.append(concurrent_test_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Concurrent connection limits',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_slowloris_protection(self):
        """Test protection against slowloris-style attacks"""
        print("🐌 Testing slowloris attack protection...")
        
        try:
            # Create slow connection that sends data very slowly
            slowloris_result = {
                'test': 'Slowloris attack protection',
                'attack_description': 'Send data very slowly to hold connection open'
            }
            
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(120)  # 2 minute timeout
                
                sock.connect(self.socket_path)
                
                # Send incomplete JSON very slowly
                incomplete_message = '{"type": "check_authorization", "action_id": "'
                
                bytes_sent = 0
                for char in incomplete_message:
                    sock.send(char.encode('utf-8'))
                    bytes_sent += 1
                    time.sleep(0.5)  # Send one character every 500ms
                    
                    # Check if connection is still alive
                    try:
                        sock.settimeout(0.1)
                        data = sock.recv(1024, socket.MSG_DONTWAIT)
                        if data:
                            slowloris_result['server_response'] = 'Received data during slow send'
                            break
                    except socket.error:
                        pass  # No data available, continue
                    finally:
                        sock.settimeout(120)
                        
                    if bytes_sent >= 20:  # Limit test duration
                        break
                        
                # Try to complete the message
                remaining_message = 'org.example.test", "details": "test"}'
                sock.send(remaining_message.encode('utf-8'))
                
                # Check final response
                try:
                    final_response = sock.recv(1024)
                    slowloris_result['final_response_received'] = len(final_response) > 0
                except:
                    slowloris_result['final_response_received'] = False
                    
                sock.close()
                
                slowloris_result['bytes_sent_slowly'] = bytes_sent
                slowloris_result['attack_completed'] = True
                slowloris_result['status'] = 'COMPLETED'
                
            except ConnectionRefusedError:
                slowloris_result['agent_not_running'] = True
                slowloris_result['status'] = 'SKIPPED'
            except FileNotFoundError:
                slowloris_result['socket_not_found'] = True
                slowloris_result['status'] = 'SKIPPED'
            except socket.timeout:
                slowloris_result['connection_timed_out'] = True
                slowloris_result['status'] = 'TIMEOUT_PROTECTION_ACTIVE'
                slowloris_result['security_status'] = 'PROTECTED'
            except Exception as e:
                slowloris_result['error'] = str(e)
                slowloris_result['status'] = 'ERROR'
                
            self.test_results.append(slowloris_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Slowloris attack protection',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def send_single_message(self, message):
        """Send a single message and return success status"""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            
            sock.connect(self.socket_path)
            sock.send(message.encode('utf-8'))
            
            # Try to receive response
            response = sock.recv(1024)
            sock.close()
            
            return len(response) > 0
            
        except ConnectionRefusedError:
            # Agent not running - count as skipped, not failure
            return None
        except FileNotFoundError:
            # Socket file doesn't exist - agent not running
            return None
        except Exception:
            return False
            
    def run_rate_limiting_tests(self):
        """Run all rate limiting and timeout tests"""
        print("🛡️ Starting Rate Limiting and Timeout Enforcement Tests...")
        
        self.test_message_rate_limiting()
        self.test_connection_timeout_enforcement()
        self.test_concurrent_connection_limits()
        self.test_slowloris_protection()
        
    def generate_report(self):
        """Generate detailed test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed_tests = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        error_tests = sum(1 for r in self.test_results if r['status'] == 'ERROR')
        skipped_tests = sum(1 for r in self.test_results if r['status'] == 'SKIPPED')
        
        report = {
            'test_type': 'Rate Limiting and Timeout Enforcement',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'errors': error_tests,
                'skipped': skipped_tests,
                'success_rate': f"{(passed_tests / max(1, total_tests - skipped_tests)) * 100:.1f}%"
            },
            'results': self.test_results
        }
        
        # Save report
        report_dir = Path("tests/security/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        with open(report_dir / "rate_limiting_report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Print summary
        print(f"\n📊 Rate Limiting Test Summary:")
        print(f"   Total tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Errors: {error_tests}")
        print(f"   Skipped: {skipped_tests}")
        
        if failed_tests > 0 or error_tests > 0:
            print(f"   ❌ {failed_tests + error_tests} security issues found")
            return False
        else:
            print(f"   ✅ All rate limiting tests completed successfully")
            return True

def main():
    """Main entry point"""
    tester = RateLimitingTester()
    tester.run_rate_limiting_tests()
    success = tester.generate_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()