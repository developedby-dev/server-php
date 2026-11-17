<?php

declare(strict_types=1);

namespace Bydev;

/**
 * 기본 HTTP GET — ext-curl이 있으면 curl, 없으면 PHP 스트림. 리다이렉트를 따라가지 않는다 · 시간 초과는 `Rules::HTTP_TIMEOUT_SEC`.
 * 프록시 · 인증서 고정이 필요하면 `ServerVerifier`에 같은 모양의 함수를 준다.
 */
final class Http
{
    /** 시험이 스트림 길을 고르려고 — null이면 저절로 */
    public static ?string $force = null;

    /**
     * @return array{0: int, 1: array<string, string>, 2: string} 상태 · 소문자 헤더 · 본문
     * @throws BydevException NETWORK_ERROR
     */
    public static function get(string $url): array
    {
        $curl = self::$force === null ? function_exists('curl_init') : self::$force === 'curl';
        return $curl ? self::curl($url) : self::stream($url);
    }

    /** @return array{0: int, 1: array<string, string>, 2: string} */
    private static function curl(string $url): array
    {
        $headers = [];
        $handle = curl_init($url);
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => Rules::HTTP_TIMEOUT_SEC,
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'User-Agent: bydev-php-server/' . Version::SDK],
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$headers): int {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return strlen($line);
            },
        ]);
        $body = curl_exec($handle);
        if ($body === false) {
            $error = curl_error($handle);
            throw new BydevException(Codes::NETWORK_ERROR, "API에 연결하지 못했다: {$error}");
        }
        return [(int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE), $headers, (string) $body];
    }

    /** @return array{0: int, 1: array<string, string>, 2: string} */
    private static function stream(string $url): array
    {
        $context = stream_context_create(['http' => [
            'method' => 'GET',
            'follow_location' => 0,
            'ignore_errors' => true,
            'timeout' => Rules::HTTP_TIMEOUT_SEC,
            'header' => "Accept: application/json\r\nUser-Agent: bydev-php-server/" . Version::SDK . "\r\n",
        ]]);
        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            throw new BydevException(Codes::NETWORK_ERROR, 'API에 연결하지 못했다');
        }
        $status = 0;
        $headers = [];
        // PHP 8.4부터 함수, 그 전은 지역 변수 $http_response_header
        $lines = function_exists('http_get_last_response_headers')
            ? (http_get_last_response_headers() ?? [])
            : ($http_response_header ?? []);
        foreach ($lines as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
                $headers = [];
                continue;
            }
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
        }
        return [$status, $headers, $body];
    }
}
