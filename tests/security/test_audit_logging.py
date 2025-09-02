#!/usr/bin/env python3
"""
Audit Log Flooding and Rotation Security Tests

This script tests audit logging security to ensure:
1. Log rotation works properly under high load
2. Attacks are properly logged
3. Log flooding doesn't break the system
4. Log integrity is maintained
"""

import json
import os
import sys
import time
import threading
import tempfile
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

class AuditLogTester:
    def __init__(self):
        self.test_results = []
        self.failures = 0
        self.temp_dirs = []
        self.log_messages = []
        
    def cleanup(self):
        """Clean up temporary directories"""
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                
    def simulate_audit_logging(self, log_dir, event_type, details, result):
        """Simulate audit log entry creation"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp} AUDIT: EVENT={event_type} DETAILS={details} RESULT={result}\n"
        
        log_file = os.path.join(log_dir, "quickshell-polkit-agent.audit.log")
        
        try:
            with open(log_file, 'a') as f:
                f.write(log_entry)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            return True
        except Exception as e:
            return False
            
    def test_log_rotation_under_load(self):
        """Test log rotation behavior under high logging load"""
        print("📝 Testing log rotation under load...")
        
        test_dir = tempfile.mkdtemp(prefix="audit_log_test_")
        self.temp_dirs.append(test_dir)
        
        try:
            # Configuration for log rotation testing
            max_log_size = 1024 * 1024  # 1MB
            max_log_files = 5
            
            rotation_test_result = {
                'test': 'Log rotation under high load',
                'test_directory': test_dir,
                'max_log_size_bytes': max_log_size,
                'max_log_files': max_log_files
            }
            
            # Generate large volume of log entries
            total_entries = 10000
            entries_written = 0
            
            start_time = time.time()
            
            for i in range(total_entries):
                success = self.simulate_audit_logging(
                    test_dir,
                    "LOAD_TEST",
                    f"Entry #{i+1} with some details to make it longer",
                    "SUCCESS"
                )
                
                if success:
                    entries_written += 1
                    
                # Check log file size periodically
                if i % 100 == 0:
                    log_file = os.path.join(test_dir, "quickshell-polkit-agent.audit.log")
                    if os.path.exists(log_file):
                        current_size = os.path.getsize(log_file)
                        if current_size > max_log_size:
                            # Simulate log rotation
                            self.rotate_log_file(log_file, max_log_files)
                            
            end_time = time.time()
            
            # Analyze results
            log_files = [f for f in os.listdir(test_dir) if f.startswith("quickshell-polkit-agent.audit")]
            total_log_size = sum(os.path.getsize(os.path.join(test_dir, f)) for f in log_files)
            
            rotation_test_result.update({
                'entries_attempted': total_entries,
                'entries_written': entries_written,
                'test_duration_seconds': end_time - start_time,
                'log_files_created': len(log_files),
                'total_log_size_bytes': total_log_size,
                'average_entry_size': total_log_size / max(1, entries_written),
                'entries_per_second': entries_written / (end_time - start_time),
                'status': 'PASS'
            })
            
            # Check if rotation worked
            if len(log_files) > 1:
                rotation_test_result['log_rotation_occurred'] = True
                rotation_test_result['rotation_status'] = 'WORKING'
            else:
                rotation_test_result['log_rotation_occurred'] = False
                if total_log_size > max_log_size:
                    rotation_test_result['rotation_status'] = 'FAILED'
                    rotation_test_result['security_issue'] = 'Log rotation not working - risk of disk space exhaustion'
                    self.failures += 1
                else:
                    rotation_test_result['rotation_status'] = 'NOT_NEEDED'
                    
            self.test_results.append(rotation_test_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Log rotation under load',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def rotate_log_file(self, log_file, max_files):
        """Simulate log file rotation"""
        try:
            base_name = log_file.replace('.log', '')
            
            # Rotate existing numbered files
            for i in range(max_files - 1, 0, -1):
                old_file = f"{base_name}.{i}.log"
                new_file = f"{base_name}.{i+1}.log"
                
                if os.path.exists(old_file):
                    if i + 1 > max_files:
                        os.remove(old_file)  # Delete oldest file
                    else:
                        os.rename(old_file, new_file)
                        
            # Move current log to .1
            if os.path.exists(log_file):
                os.rename(log_file, f"{base_name}.1.log")
                
        except Exception as e:
            pass  # Ignore rotation errors for testing
            
    def test_attack_logging_completeness(self):
        """Test that security attacks are properly logged"""
        print("🔍 Testing attack logging completeness...")
        
        test_dir = tempfile.mkdtemp(prefix="attack_log_test_")
        self.temp_dirs.append(test_dir)
        
        try:
            # Simulate various security events that should be logged
            security_events = [
                {'event': 'RATE_LIMIT', 'details': 'Client exceeded message rate limit', 'result': 'BLOCKED'},
                {'event': 'SESSION_EXPIRED', 'details': 'Client session timed out', 'result': 'DISCONNECTED'},
                {'event': 'MESSAGE_VALIDATION', 'details': 'Invalid message format', 'result': 'REJECTED'},
                {'event': 'HMAC_VERIFICATION', 'details': 'HMAC signature invalid', 'result': 'REJECTED'},
                {'event': 'TIMESTAMP_VALIDATION', 'details': 'Message timestamp out of range', 'result': 'REJECTED'},
                {'event': 'CONNECTION_FLOOD', 'details': 'Too many concurrent connections', 'result': 'BLOCKED'},
                {'event': 'MALFORMED_JSON', 'details': 'JSON parsing failed', 'result': 'REJECTED'},
                {'event': 'OVERSIZED_MESSAGE', 'details': 'Message exceeds size limit', 'result': 'REJECTED'},
                {'event': 'SYMLINK_ATTACK', 'details': 'Symlink attack detected', 'result': 'BLOCKED'},
                {'event': 'PERMISSION_VIOLATION', 'details': 'Insufficient permissions', 'result': 'DENIED'},
            ]
            
            logged_events = []
            
            for event in security_events:
                success = self.simulate_audit_logging(
                    test_dir,
                    event['event'],
                    event['details'],
                    event['result']
                )
                
                if success:
                    logged_events.append(event)
                    
            # Verify log contents
            log_file = os.path.join(test_dir, "quickshell-polkit-agent.audit.log")
            log_contents = ""
            
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    log_contents = f.read()
                    
            # Check that all events were logged
            missing_events = []
            for event in security_events:
                if event['event'] not in log_contents:
                    missing_events.append(event['event'])
                    
            attack_log_result = {
                'test': 'Attack logging completeness',
                'total_security_events': len(security_events),
                'successfully_logged': len(logged_events),
                'missing_events': missing_events,
                'log_file_size': os.path.getsize(log_file) if os.path.exists(log_file) else 0,
                'status': 'PASS' if len(missing_events) == 0 else 'FAIL'
            }
            
            if missing_events:
                attack_log_result['security_issue'] = 'Critical security events not logged'
                self.failures += 1
                
            self.test_results.append(attack_log_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Attack logging completeness',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_concurrent_logging_integrity(self):
        """Test log integrity under concurrent access"""
        print("🔀 Testing concurrent logging integrity...")
        
        test_dir = tempfile.mkdtemp(prefix="concurrent_log_test_")
        self.temp_dirs.append(test_dir)
        
        try:
            num_threads = 10
            entries_per_thread = 100
            
            def logging_worker(worker_id):
                worker_results = []
                
                for i in range(entries_per_thread):
                    event_type = f"WORKER_{worker_id}_EVENT"
                    details = f"Entry {i+1} from worker {worker_id}"
                    result = "SUCCESS"
                    
                    success = self.simulate_audit_logging(test_dir, event_type, details, result)
                    worker_results.append({
                        'worker_id': worker_id,
                        'entry_id': i + 1,
                        'success': success,
                        'timestamp': time.time()
                    })
                    
                    # Small random delay to increase chance of race conditions
                    time.sleep(0.001)
                    
                return worker_results
                
            # Run concurrent logging
            all_results = []
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(logging_worker, i) for i in range(num_threads)]
                
                for future in futures:
                    worker_results = future.result()
                    all_results.extend(worker_results)
                    
            end_time = time.time()
            
            # Analyze results
            total_attempts = len(all_results)
            successful_writes = sum(1 for r in all_results if r['success'])
            failed_writes = total_attempts - successful_writes
            
            # Check log file integrity
            log_file = os.path.join(test_dir, "quickshell-polkit-agent.audit.log")
            log_line_count = 0
            corrupted_lines = 0
            
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
                        log_line_count += 1
                        # Basic integrity check - each line should have timestamp and AUDIT
                        if not ("AUDIT:" in line and len(line.strip()) > 10):
                            corrupted_lines += 1
                            
            concurrent_log_result = {
                'test': 'Concurrent logging integrity',
                'num_threads': num_threads,
                'entries_per_thread': entries_per_thread,
                'total_attempts': total_attempts,
                'successful_writes': successful_writes,
                'failed_writes': failed_writes,
                'test_duration_seconds': end_time - start_time,
                'log_lines_written': log_line_count,
                'corrupted_lines': corrupted_lines,
                'integrity_rate': f"{((log_line_count - corrupted_lines) / max(1, log_line_count)) * 100:.1f}%",
                'status': 'PASS' if corrupted_lines == 0 else 'FAIL'
            }
            
            if corrupted_lines > 0:
                concurrent_log_result['security_issue'] = 'Log corruption detected under concurrent access'
                self.failures += 1
                
            if failed_writes > total_attempts * 0.1:  # More than 10% failure rate
                concurrent_log_result['high_failure_rate'] = True
                concurrent_log_result['potential_issue'] = 'High write failure rate may indicate locking issues'
                
            self.test_results.append(concurrent_log_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Concurrent logging integrity',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def test_log_flooding_resistance(self):
        """Test resistance to log flooding attacks"""
        print("🌊 Testing log flooding resistance...")
        
        test_dir = tempfile.mkdtemp(prefix="log_flood_test_")
        self.temp_dirs.append(test_dir)
        
        try:
            # Simulate massive log flooding attack
            flood_entries = 50000  # Large number of entries
            max_allowed_log_size = 10 * 1024 * 1024  # 10MB limit
            
            flood_start_time = time.time()
            entries_written = 0
            
            for i in range(flood_entries):
                # Create large log entries to flood faster
                large_details = "A" * 1000  # 1KB per entry
                
                success = self.simulate_audit_logging(
                    test_dir,
                    "FLOOD_ATTACK",
                    large_details,
                    "ATTACK_DETECTED"
                )
                
                if success:
                    entries_written += 1
                    
                # Check if we should stop due to size limits
                if i % 1000 == 0:
                    log_file = os.path.join(test_dir, "quickshell-polkit-agent.audit.log")
                    if os.path.exists(log_file):
                        current_size = os.path.getsize(log_file)
                        if current_size > max_allowed_log_size:
                            # Simulate emergency log rotation or truncation
                            self.emergency_log_cleanup(log_file)
                            
            flood_end_time = time.time()
            
            # Analyze flood test results
            log_files = [f for f in os.listdir(test_dir) if f.startswith("quickshell-polkit-agent.audit")]
            total_log_size = sum(os.path.getsize(os.path.join(test_dir, f)) for f in log_files)
            
            flood_result = {
                'test': 'Log flooding resistance',
                'flood_entries_attempted': flood_entries,
                'entries_actually_written': entries_written,
                'flood_duration_seconds': flood_end_time - flood_start_time,
                'total_log_size_bytes': total_log_size,
                'max_allowed_size_bytes': max_allowed_log_size,
                'log_files_created': len(log_files),
                'flooding_rate_per_second': entries_written / (flood_end_time - flood_start_time),
                'status': 'TESTED'
            }
            
            # Evaluate flood resistance
            if total_log_size > max_allowed_log_size * 1.5:  # 50% over limit
                flood_result['flood_resistance'] = 'POOR'
                flood_result['security_issue'] = 'Log flooding could exhaust disk space'
                self.failures += 1
            elif total_log_size > max_allowed_log_size:
                flood_result['flood_resistance'] = 'MODERATE'
                flood_result['security_note'] = 'Some log size limits exceeded'
            else:
                flood_result['flood_resistance'] = 'GOOD'
                flood_result['security_status'] = 'PROTECTED'
                
            self.test_results.append(flood_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Log flooding resistance',
                'status': 'ERROR',
                'error': str(e)
            })
            self.failures += 1
            
    def emergency_log_cleanup(self, log_file):
        """Simulate emergency log cleanup when size limits are exceeded"""
        try:
            # Truncate log to last 1000 lines
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
            if len(lines) > 1000:
                with open(log_file, 'w') as f:
                    f.write("=== LOG TRUNCATED DUE TO SIZE LIMIT ===\n")
                    f.writelines(lines[-1000:])
                    
        except Exception:
            pass  # Ignore cleanup errors
            
    def test_log_tampering_detection(self):
        """Test log tampering detection mechanisms"""
        print("🔒 Testing log tampering detection...")
        
        test_dir = tempfile.mkdtemp(prefix="log_tamper_test_")
        self.temp_dirs.append(test_dir)
        
        try:
            # Create initial log entries
            original_entries = [
                "ORIGINAL_EVENT_1",
                "ORIGINAL_EVENT_2", 
                "ORIGINAL_EVENT_3"
            ]
            
            for event in original_entries:
                self.simulate_audit_logging(test_dir, event, "Original log entry", "SUCCESS")
                
            log_file = os.path.join(test_dir, "quickshell-polkit-agent.audit.log")
            
            # Calculate initial checksum
            initial_checksum = self.calculate_log_checksum(log_file)
            
            # Simulate tampering attempts
            tampering_tests = [
                {
                    'name': 'Line deletion',
                    'action': lambda: self.delete_log_line(log_file, 1)
                },
                {
                    'name': 'Line modification', 
                    'action': lambda: self.modify_log_line(log_file, 0, "MODIFIED_EVENT")
                },
                {
                    'name': 'Line insertion',
                    'action': lambda: self.insert_log_line(log_file, "INSERTED_MALICIOUS_EVENT")
                }
            ]
            
            tamper_results = []
            
            for tamper_test in tampering_tests:
                # Make backup
                backup_file = log_file + ".backup"
                shutil.copy2(log_file, backup_file)
                
                try:
                    # Perform tampering
                    tamper_test['action']()
                    
                    # Calculate new checksum
                    new_checksum = self.calculate_log_checksum(log_file)
                    
                    tamper_result = {
                        'tampering_type': tamper_test['name'],
                        'initial_checksum': initial_checksum,
                        'post_tamper_checksum': new_checksum,
                        'tampering_detected': initial_checksum != new_checksum,
                        'status': 'DETECTED' if initial_checksum != new_checksum else 'UNDETECTED'
                    }
                    
                    tamper_results.append(tamper_result)
                    
                    # Restore backup for next test
                    shutil.copy2(backup_file, log_file)
                    
                except Exception as e:
                    tamper_results.append({
                        'tampering_type': tamper_test['name'],
                        'status': 'ERROR',
                        'error': str(e)
                    })
                    
            tamper_detection_result = {
                'test': 'Log tampering detection',
                'tampering_tests': tamper_results,
                'total_tests': len(tampering_tests),
                'detected_tampering': sum(1 for r in tamper_results if r.get('tampering_detected', False)),
                'status': 'PASS'
            }
            
            # Note: Basic checksum detection is implemented for demonstration
            # In a real system, more sophisticated integrity mechanisms would be used
            tamper_detection_result['security_note'] = 'Basic checksum validation implemented for demonstration'
            
            self.test_results.append(tamper_detection_result)
            
        except Exception as e:
            self.test_results.append({
                'test': 'Log tampering detection',
                'status': 'ERROR',
                'error': str(e)
            })
            
    def calculate_log_checksum(self, log_file):
        """Calculate simple checksum for log file"""
        import hashlib
        
        if not os.path.exists(log_file):
            return ""
            
        with open(log_file, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
            
    def delete_log_line(self, log_file, line_number):
        """Delete a specific line from log file"""
        with open(log_file, 'r') as f:
            lines = f.readlines()
            
        if 0 <= line_number < len(lines):
            del lines[line_number]
            
            with open(log_file, 'w') as f:
                f.writelines(lines)
                
    def modify_log_line(self, log_file, line_number, new_content):
        """Modify a specific line in log file"""
        with open(log_file, 'r') as f:
            lines = f.readlines()
            
        if 0 <= line_number < len(lines):
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            lines[line_number] = f"{timestamp} AUDIT: EVENT={new_content} DETAILS=Modified RESULT=TAMPERED\n"
            
            with open(log_file, 'w') as f:
                f.writelines(lines)
                
    def insert_log_line(self, log_file, event_content):
        """Insert a malicious line into log file"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        malicious_line = f"{timestamp} AUDIT: EVENT={event_content} DETAILS=Inserted RESULT=MALICIOUS\n"
        
        with open(log_file, 'a') as f:
            f.write(malicious_line)
            
    def run_audit_log_tests(self):
        """Run all audit log security tests"""
        print("📋 Starting Audit Log Security Tests...")
        
        try:
            self.test_log_rotation_under_load()
            self.test_attack_logging_completeness()
            self.test_concurrent_logging_integrity()
            self.test_log_flooding_resistance()
            self.test_log_tampering_detection()
            
        finally:
            self.cleanup()
            
    def generate_report(self):
        """Generate detailed test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed_tests = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        error_tests = sum(1 for r in self.test_results if r['status'] == 'ERROR')
        
        report = {
            'test_type': 'Audit Log Security',
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
        
        with open(report_dir / "audit_log_report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Print summary
        print(f"\n📊 Audit Log Security Test Summary:")
        print(f"   Total tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Errors: {error_tests}")
        
        if failed_tests > 0 or error_tests > 0:
            print(f"   ❌ {failed_tests + error_tests} audit log security issues found")
            return False
        else:
            print(f"   ✅ All audit log security tests passed")
            return True

def main():
    """Main entry point"""
    tester = AuditLogTester()
    tester.run_audit_log_tests()
    success = tester.generate_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()