"""Test script for the complete phishing detection system."""

import asyncio
import httpx
import json
from typing import Dict, Any

BASE_URL = "http://localhost:8000"


async def test_health():
    """Test health endpoint."""
    print("\n" + "="*60)
    print("Testing Health Endpoint")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")


async def test_auth():
    """Test authentication endpoints."""
    print("\n" + "="*60)
    print("Testing Authentication")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        # Register
        print("\n1. Registering user...")
        response = await client.post(
            f"{BASE_URL}/auth/register",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 201:
            print(f"User created: {response.json()}")
        else:
            print(f"Error: {response.json()}")
        
        # Login
        print("\n2. Logging in...")
        response = await client.post(
            f"{BASE_URL}/auth/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            token_data = response.json()
            print(f"Token received: {token_data['access_token'][:50]}...")
            return token_data['access_token']
        else:
            print(f"Error: {response.json()}")
            return None


async def test_scan(token: str):
    """Test scan endpoint."""
    print("\n" + "="*60)
    print("Testing Scan")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {token}"}
        
        # Suspicious page
        print("\n1. Scanning suspicious page...")
        response = await client.post(
            f"{BASE_URL}/scans",
            headers=headers,
            json={
                "page_data": {
                    "url": "https://secure-login-bank.com/verify",
                    "domain": "secure-login-bank.com",
                    "title": "Secure Bank Login - Verify Your Account",
                    "visible_text": "Enter your username and password to verify your account",
                    "forms": [
                        {
                            "action": "/login",
                            "method": "post",
                            "fields": ["username", "password"]
                        }
                    ]
                }
            },
            timeout=30.0
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 201:
            result = response.json()
            print(f"Scan ID: {result['scan_id']}")
            print(f"Risk Score: {result['risk']['score']:.2f}")
            print(f"Risk Level: {result['risk']['level']}")
            print(f"Classification: {result['classification']}")
            print(f"\nSignals:")
            print(f"  Kev available: {result['signals']['kev']['available']}")
            if result['signals']['kev']['available']:
                print(f"  Phishing: {result['signals']['kev']['is_phishing']:.2f}")
                print(f"  Malicious: {result['signals']['kev']['is_malicious']:.2f}")
            print(f"  Rules triggered: {result['signals']['rules']['rule_count']}")
            print(f"  ML available: {result['signals']['ml']['available']}")
            if result['signals']['ml']['available']:
                print(f"  ML score: {result['signals']['ml']['score']:.2f}")
        else:
            print(f"Error: {response.json()}")
        
        # Benign page
        print("\n2. Scanning benign page...")
        response = await client.post(
            f"{BASE_URL}/scans",
            headers=headers,
            json={
                "page_data": {
                    "url": "https://example.com",
                    "domain": "example.com",
                    "title": "Example Domain",
                    "visible_text": "This domain is for use in illustrative examples."
                }
            },
            timeout=30.0
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 201:
            result = response.json()
            print(f"Scan ID: {result['scan_id']}")
            print(f"Risk Score: {result['risk']['score']:.2f}")
            print(f"Risk Level: {result['risk']['level']}")


async def test_history(token: str):
    """Test scan history."""
    print("\n" + "="*60)
    print("Testing Scan History")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {token}"}
        
        response = await client.get(
            f"{BASE_URL}/scans",
            headers=headers
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            scans = response.json()
            print(f"Total scans: {len(scans)}")
            for scan in scans[:3]:
                print(f"  - {scan['scan_id'][:8]}... | {scan['domain']} | Risk: {scan['risk_score']:.2f}")


async def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("PHISHING DETECTION SYSTEM - INTEGRATION TEST")
    print("="*60)
    
    try:
        await test_health()
        token = await test_auth()
        
        if token:
            await test_scan(token)
            await test_history(token)
        
        print("\n" + "="*60)
        print("TESTS COMPLETED SUCCESSFULLY")
        print("="*60)
        
    except httpx.ConnectError:
        print("\nERROR: Backend is not running!")
        print("Start it with: uvicorn app.main:app --reload")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
