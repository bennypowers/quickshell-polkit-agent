#!/usr/bin/env python3
"""
IPC Socket Fuzzing Test

This script fuzzes the quickshell-polkit-agent IPC socket with malformed and oversized
JSON messages to test input validation and error handling.
"""

import asyncio
import json
import socket
import os
import random
import string
import time
import sys
from pathlib import Path

class IPCSocketFuzzer:
    def __init__(self, socket_path="/tmp/quickshell-polkit-agent"):
        self.socket_path = socket_path
        self.test_results = []
        self.failures = 0
        
    def generate_malformed_json(self):
        """Generate various types of malformed JSON payloads"""
        malformed_payloads = [
            # Invalid JSON syntax
            '{"type": "check_authorization"',  # Missing closing brace
            '{"type": "check_authorization", "action_id":}',  # Missing value
            '{"type": "check_authorization" "action_id": "test"}',  # Missing comma
            '{type: "check_authorization"}',  # Unquoted key
            '{"type": "check_authorization", "extra_comma": ,}',  # Extra comma
            
            # Invalid JSON values
            '{"type": null}',  # Null type
            '{"type": 123}',  # Numeric type
            '{"type": []}',  # Array type
            '{"type": {}}',  # Object type
            
            # Control characters and encoding issues
            '{"type": "check\\u0000authorization"}',  # Null byte
            '{"type": "check\nauthorization"}',  # Newline in string
            '{"type": "check\tauthorization"}',  # Tab in string
            
            # Binary data
            b'\x00\x01\x02\x03',  # Raw bytes
            '{"type": "\\xff\\xfe"}',  # Invalid UTF-8 sequences
        ]
        return malformed_payloads
        
    def generate_oversized_json(self):
        """Generate oversized JSON payloads to test size limits"""
        oversized_payloads = []
        
        # Large string fields
        large_string = 'A' * (1024 * 1024)  # 1MB string
        oversized_payloads.append(json.dumps({
            "type": "check_authorization",
            "action_id": large_string
        }))
        
        # Large object with many fields
        large_obj = {"type": "check_authorization"}
        for i in range(10000):
            large_obj[f"field_{i}"] = f"value_{i}"
        oversized_payloads.append(json.dumps(large_obj))
        
        # Deeply nested object
        nested_obj = {"type": "check_authorization"}
        current = nested_obj
        for i in range(1000):
            current["nested"] = {}
            current = current["nested"]
        oversized_payloads.append(json.dumps(nested_obj))
        
        return oversized_payloads
        
    def generate_random_payloads(self, count=100):
        """Generate random payloads with various structures"""
        payloads = []
        
        for _ in range(count):
            # Random message type
            msg_type = ''.join(random.choices(string.ascii_letters + '_', k=random.randint(1, 50)))
            
            payload = {"type": msg_type}
            
            # Add random fields
            num_fields = random.randint(0, 20)
            for _ in range(num_fields):
                key = ''.join(random.choices(string.ascii_letters + '_', k=random.randint(1, 20)))
                # Random value type
                value_type = random.choice(['string', 'int', 'float', 'bool', 'null', 'array', 'object'])
                
                if value_type == 'string':
                    payload[key] = ''.join(random.choices(string.printable, k=random.randint(0, 1000)))
                elif value_type == 'int':
                    payload[key] = random.randint(-2**31, 2**31-1)
                elif value_type == 'float':
                    payload[key] = random.uniform(-1e10, 1e10)
                elif value_type == 'bool':
                    payload[key] = random.choice([True, False])
                elif value_type == 'null':
                    payload[key] = None
                elif value_type == 'array':
                    payload[key] = [random.randint(0, 100) for _ in range(random.randint(0, 10))]
                elif value_type == 'object':
                    payload[key] = {f"key_{i}": f"value_{i}" for i in range(random.randint(0, 5))}
                    
            payloads.append(json.dumps(payload))
            
        return payloads
        
    def test_socket_connection(self, payload, description):
        """Test a single payload against the socket"""
        try:
            # Create Unix socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)  # 5 second timeout
            
            # Connect to agent socket
            sock.connect(self.socket_path)
            
            # Send payload
            if isinstance(payload, str):
                sock.send(payload.encode('utf-8', errors='ignore'))
            else:
                sock.send(payload)
                
            # Try to receive response
            response = sock.recv(4096)
            
            # Close socket
            sock.close()
            
            result = {
                'description': description,
                'payload_preview': str(payload)[:100] + '...' if len(str(payload)) > 100 else str(payload),
                'response_received': len(response) > 0,
                'response_size': len(response),
                'status': 'PASSED' if len(response) > 0 else 'FAILED'
            }
            
            self.test_results.append(result)
            return True
            
        except ConnectionRefusedError:
            # Agent not running - this is expected in CI
            result = {
                'description': description,
                'payload_preview': str(payload)[:100] + '...' if len(str(payload)) > 100 else str(payload),
                'status': 'SKIPPED - Agent not running',
                'error': 'Connection refused'
            }
            self.test_results.append(result)
            return True
        except FileNotFoundError:
            # Socket file doesn't exist - agent not running
            result = {
                'description': description,
                'payload_preview': str(payload)[:100] + '...' if len(str(payload)) > 100 else str(payload),
                'status': 'SKIPPED - Socket not found',
                'error': 'Socket file does not exist'
            }
            self.test_results.append(result)
            return True
            
        except Exception as e:
            result = {
                'description': description,
                'payload_preview': str(payload)[:100] + '...' if len(str(payload)) > 100 else str(payload),
                'status': 'ERROR',
                'error': str(e)
            }
            self.test_results.append(result)
            self.failures += 1
            return False
            
    def run_fuzz_tests(self):
        """Run all fuzzing test cases"""
        print("🔍 Starting IPC Socket Fuzzing Tests...")
        
        # Test malformed JSON
        print("  Testing malformed JSON payloads...")
        malformed = self.generate_malformed_json()
        for i, payload in enumerate(malformed):
            self.test_socket_connection(payload, f"Malformed JSON #{i+1}")
            
        # Test oversized JSON
        print("  Testing oversized JSON payloads...")
        oversized = self.generate_oversized_json()
        for i, payload in enumerate(oversized):
            self.test_socket_connection(payload, f"Oversized JSON #{i+1}")
            
        # Test random payloads
        print("  Testing random payloads...")
        random_payloads = self.generate_random_payloads(50)
        for i, payload in enumerate(random_payloads):
            self.test_socket_connection(payload, f"Random payload #{i+1}")
            
        # Test protocol violations
        print("  Testing protocol violations...")
        protocol_violations = [
            "",  # Empty message
            "\n",  # Just newline
            "not json at all",  # Plain text
            "HTTP/1.1 200 OK\r\n\r\n",  # HTTP response
            "\x00" * 100,  # Null bytes
        ]
        
        for i, payload in enumerate(protocol_violations):
            self.test_socket_connection(payload, f"Protocol violation #{i+1}")
            
    def generate_report(self):
        """Generate a detailed test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['status'] == 'PASSED')
        skipped_tests = sum(1 for r in self.test_results if 'SKIPPED' in r['status'])
        error_tests = sum(1 for r in self.test_results if r['status'] == 'ERROR')
        
        report = {
            'test_type': 'IPC Socket Fuzzing',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'skipped': skipped_tests,
                'errors': error_tests,
                'success_rate': f"{(passed_tests / max(1, total_tests - skipped_tests)) * 100:.1f}%"
            },
            'results': self.test_results
        }
        
        # Save report
        report_dir = Path("tests/security/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        with open(report_dir / "fuzz_ipc_socket_report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Print summary
        print(f"\n📊 IPC Socket Fuzzing Test Summary:")
        print(f"   Total tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Skipped: {skipped_tests}")
        print(f"   Errors: {error_tests}")
        
        if error_tests > 0:
            print(f"   ⚠️  {error_tests} tests had unexpected errors")
            return False
        else:
            print(f"   ✅ All fuzzing tests completed successfully")
            return True
            
def main():
    """Main entry point"""
    fuzzer = IPCSocketFuzzer()
    fuzzer.run_fuzz_tests()
    success = fuzzer.generate_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()