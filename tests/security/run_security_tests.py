#!/usr/bin/env python3
"""
Security Test Runner

This script runs all security tests and generates a comprehensive report.
"""

import subprocess
import sys
import time
import json
from pathlib import Path

def run_security_test(test_script):
    """Run a single security test script"""
    print(f"\n🔍 Running {test_script}...")
    
    try:
        result = subprocess.run(
            [sys.executable, test_script],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        return {
            'script': test_script,
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'success': result.returncode == 0
        }
        
    except subprocess.TimeoutExpired:
        return {
            'script': test_script,
            'exit_code': -1,
            'error': 'Test timed out after 5 minutes',
            'success': False
        }
    except Exception as e:
        return {
            'script': test_script,
            'exit_code': -1,
            'error': str(e),
            'success': False
        }

def main():
    """Main test runner"""
    print("🛡️ Starting Comprehensive Security Test Suite...")
    
    # Security test scripts to run
    security_tests = [
        "tests/security/fuzz_ipc_socket.py",
        "tests/security/test_permissions.py",
        "tests/security/test_replay_attacks.py", 
        "tests/security/test_rate_limiting.py",
        "tests/security/test_audit_logging.py",
        "tests/security/test_ui_confusion.py"
    ]
    
    # Ensure reports directory exists
    reports_dir = Path("tests/security/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Run all tests
    test_results = []
    start_time = time.time()
    
    for test_script in security_tests:
        if Path(test_script).exists():
            result = run_security_test(test_script)
            test_results.append(result)
            
            if result['success']:
                print(f"   ✅ {test_script} - PASSED")
            else:
                print(f"   ❌ {test_script} - FAILED")
                if 'stderr' in result and result['stderr']:
                    print(f"      Error: {result['stderr'][:200]}...")
        else:
            print(f"   ⚠️  {test_script} - NOT FOUND")
            test_results.append({
                'script': test_script,
                'exit_code': -1,
                'error': 'Test script not found',
                'success': False
            })
            
    end_time = time.time()
    
    # Generate summary report
    total_tests = len(test_results)
    passed_tests = sum(1 for r in test_results if r['success'])
    failed_tests = total_tests - passed_tests
    
    summary_report = {
        'test_suite': 'Security Test Suite',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration_seconds': end_time - start_time,
        'summary': {
            'total_test_scripts': total_tests,
            'passed_scripts': passed_tests,
            'failed_scripts': failed_tests,
            'success_rate': f"{(passed_tests / max(1, total_tests) * 100):.1f}%"
        },
        'test_results': test_results
    }
    
    # Save summary report
    with open(reports_dir / "security_test_summary.json", "w") as f:
        json.dump(summary_report, f, indent=2)
        
    # Print final summary
    print(f"\n📊 Security Test Suite Summary:")
    print(f"   Total test scripts: {total_tests}")
    print(f"   Passed: {passed_tests}")
    print(f"   Failed: {failed_tests}")
    print(f"   Duration: {end_time - start_time:.1f} seconds")
    print(f"   Success rate: {(passed_tests / max(1, total_tests) * 100):.1f}%")
    
    if failed_tests > 0:
        print(f"\n❌ Security test suite FAILED - {failed_tests} test scripts failed")
        print("   Check individual test reports in tests/security/reports/")
        return 1
    else:
        print(f"\n✅ Security test suite PASSED - All security tests completed successfully")
        return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)