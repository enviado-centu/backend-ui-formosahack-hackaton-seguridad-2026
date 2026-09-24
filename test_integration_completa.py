"""Script de prueba para la integración completa desde el backend."""

import sys
from pathlib import Path

BACKEND_PATH = Path(__file__).parent
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

MODULO_PY_PATH = BACKEND_PATH.parent / "MODULO-PY"
if str(MODULO_PY_PATH) not in sys.path:
    sys.path.insert(0, str(MODULO_PY_PATH))

KEV_PATH = BACKEND_PATH.parent / "kev_integration"
if str(KEV_PATH) not in sys.path:
    sys.path.insert(0, str(KEV_PATH))


def test_motor_reglas():
    """Prueba el motor de reglas de MODULO-PY."""
    print("=" * 60)
    print("TEST 1: Motor de Reglas MODULO-PY")
    print("=" * 60)
    
    from motor.reglas import evaluar_reglas
    from motor.listas import esta_en_lista_negra, es_oficial
    
    urls_test = [
        "http://paypal-login.xyz",
        "https://www.google.com",
        "http://192.168.1.1/login",
    ]
    
    for url in urls_test:
        print(f"\nURL: {url}")
        senales = evaluar_reglas(url)
        
        if senales:
            print(f"  Señales: {len(senales)}")
            for s in senales:
                print(f"    - {s.id}: {s.frase}")
            
            total_puntos = sum(s.puntos for s in senales)
            risk_score = min(1.0, total_puntos / 100.0)
            print(f"  Risk score: {risk_score:.2f}")
        else:
            print("  No se detectaron señales")


def test_backend_integration():
    """Prueba la integración con el backend."""
    print("\n" + "=" * 60)
    print("TEST 2: Integración Backend")
    print("=" * 60)
    
    from app.integrations.modulo_py.integration import ModuloPyIntegration
    
    integration = ModuloPyIntegration()
    
    print(f"\nMotor disponible: {integration.motor_available}")
    print(f"Features disponible: {integration.features_available}")
    print(f"Predict disponible: {integration.predict_available}")
    
    url_test = "http://paypal-login.xyz"
    print(f"\nAnalizando URL: {url_test}")
    
    rules_result = integration.analyze_rules(url_test)
    print(f"\nRules Engine:")
    print(f"  Disponible: {rules_result.available}")
    print(f"  Reglas activadas: {rules_result.rule_count}")
    print(f"  Risk score: {rules_result.risk_score:.2f}")
    if rules_result.triggered_rules:
        print(f"  Reglas: {', '.join(rules_result.triggered_rules)}")
    
    ml_result = integration.analyze_ml(url_test)
    print(f"\nML Engine:")
    print(f"  Disponible: {ml_result.available}")
    if ml_result.available:
        print(f"  Score: {ml_result.score:.2f}")
        print(f"  Predicción: {'Phishing' if ml_result.prediction == 0 else 'Legítimo'}")
    else:
        print(f"  Error: {ml_result.error}")


def test_kev_integration():
    """Prueba la integración con Kev."""
    print("\n" + "=" * 60)
    print("TEST 3: Integración Kev")
    print("=" * 60)
    
    try:
        from kev_integration import KevService, PageAnalysisRequest, KevConfig
        
        config = KevConfig(base_url="http://localhost:8009", timeout=5)
        service = KevService(config)
        
        print("Kev service inicializado")
        
        request = PageAnalysisRequest(
            url="http://paypal-login.xyz",
            domain="paypal-login.xyz",
            title="Login",
            visible_text="Enter your credentials",
        )
        
        print(f"\nAnalizando URL: {request.url}")
        result = service.analyze(request)
        
        print(f"\nKev Results:")
        print(f"  Phishing: {result.is_phishing.probability:.2f}")
        print(f"  Malicious: {result.is_malicious.probability:.2f}")
        print(f"  Threat type: {result.threat_type.value}")
        print(f"  Risk score: {result.risk.score:.2f}")
        
    except Exception as e:
        print(f"Kev no disponible: {e}")
        print("(Esto es normal si Kev no está corriendo)")


def test_full_integration():
    """Prueba la integración completa de los tres componentes."""
    print("\n" + "=" * 60)
    print("TEST 4: Integración Completa")
    print("=" * 60)
    
    from motor.reglas import evaluar_reglas
    from app.integrations.modulo_py.integration import ModuloPyIntegration
    
    url_test = "http://paypal-login.xyz"
    print(f"\nURL a analizar: {url_test}")
    
    print("\n1. MODULO-PY Motor:")
    senales = evaluar_reglas(url_test)
    print(f"   Señales: {len(senales)}")
    for s in senales:
        print(f"     - {s.id}: {s.frase}")
    
    print("\n2. MODULO-PY Backend Integration:")
    integration = ModuloPyIntegration()
    rules_result = integration.analyze_rules(url_test)
    print(f"   Risk score: {rules_result.risk_score:.2f}")
    print(f"   Reglas: {rules_result.rule_count}")
    
    print("\n3. Kev Integration:")
    try:
        from kev_integration import KevService, PageAnalysisRequest, KevConfig
        config = KevConfig(base_url="http://localhost:8009", timeout=5)
        service = KevService(config)
        request = PageAnalysisRequest(url=url_test, domain="paypal-login.xyz")
        result = service.analyze(request)
        print(f"   Phishing: {result.is_phishing.probability:.2f}")
        print(f"   Risk: {result.risk.score:.2f}")
    except Exception as e:
        print(f"   No disponible: {e}")
    
    print("\n4. Risk Assessment Combinado:")
    print("   (Se calcula en el backend combinando todas las señales)")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("PRUEBA DE INTEGRACIÓN: Kev + MODULO-PY + Backend")
    print("=" * 60)
    
    test_motor_reglas()
    test_backend_integration()
    test_kev_integration()
    test_full_integration()
    
    print("\n" + "=" * 60)
    print("PRUEBAS COMPLETADAS")
    print("=" * 60)
