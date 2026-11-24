from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.graph.builder import build_threat_graph


def test_build_threat_graph_structure():
    url = "https://paypa1-security.com/login?auth=1"
    features = extract_features(url)
    brand_match = detect_brand_impersonation(features.sld, url)

    # Build graph with skip_network_calls=True to test deterministic structure
    graph = build_threat_graph(features, brand_match, skip_network_calls=True)

    node_types = {n.type for n in graph.nodes}
    assert "url" in node_types
    assert "hostname" in node_types
    assert "domain" in node_types
    assert "brand_target" in node_types

    edge_relationships = {e.relationship for e in graph.edges}
    assert "CONTAINS_HOST" in edge_relationships
    assert "TARGETS_BRAND" in edge_relationships

    # Check serialization
    graph_dict = graph.to_dict()
    assert "nodes" in graph_dict
    assert "edges" in graph_dict
    assert "summary" in graph_dict
    assert "threat_indicators" in graph_dict
    assert len(graph_dict["threat_indicators"]) > 0
