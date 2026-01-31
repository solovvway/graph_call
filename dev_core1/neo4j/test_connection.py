#!/usr/bin/env python3
"""Test script to verify Neo4j connection."""

import sys
from neo4j import GraphDatabase

def test_connection(uri="bolt://localhost:7687", user="neo4j", password="password"):
    """Test connection to Neo4j."""
    print(f"Testing connection to {uri}...")
    
    # Use IPv4 explicitly if localhost is used to avoid IPv6 timeout issues
    if "localhost" in uri and "127.0.0.1" not in uri:
        uri = uri.replace("localhost", "127.0.0.1")
        print(f"Using IPv4 address: {uri}")
    
    try:
        driver = GraphDatabase.driver(
            uri, 
            auth=(user, password),
            connection_timeout=30,
            max_connection_lifetime=3600
        )
        
        # Verify connection
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            record = result.single()
            print(f"✓ Connection successful! Test result: {record['test']}")
            return True
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        return False
    finally:
        if 'driver' in locals():
            driver.close()

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
