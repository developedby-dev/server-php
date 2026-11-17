<?php

// php -S 시험 서버 — 발견 문서 · JWKS(환경 변수 BYDEV_TEST_X의 공개키), 리다이렉트 하나
$base = 'http://' . $_SERVER['HTTP_HOST'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
header('Content-Type: application/json');
header('X-Correlation-Id: req_php0001');
if ($path === '/.well-known/openid-configuration') {
    echo json_encode(['issuer' => $base, 'jwks_uri' => $base . '/.well-known/jwks.json']);
} elseif ($path === '/.well-known/jwks.json') {
    header('Cache-Control: public, max-age=300');
    echo json_encode(['keys' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'srv-k1', 'alg' => 'EdDSA', 'use' => 'sig', 'x' => getenv('BYDEV_TEST_X')]]]);
} elseif ($path === '/redirect') {
    header('Location: /.well-known/jwks.json', true, 302);
} else {
    http_response_code(404);
    echo json_encode(['code' => 'PRODUCT_NOT_FOUND', 'message' => '없음']);
}
