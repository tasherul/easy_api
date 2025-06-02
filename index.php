<?php

// ===================== ROUTES =====================

/**
 * @route POST /login
 * @desc Login and receive JWT token
 * @tag Public
 * @body {"username":"admin","password":"password"}
 * @response 200 {"token":"<jwt_token>"}
 */
function postLogin() {
    $input = json_decode(file_get_contents('php://input'), true);
    if ($input['username'] === 'admin' && $input['password'] === 'password') {
        $header = App::b64url(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = App::b64url(json_encode(['user' => 'admin', 'iat' => time(), 'exp' => time() + 3600]));
        $signature = App::b64url(App::hmac("$header.$payload"));
        App::respond(['token' => "$header.$payload.$signature"]);
    }
    App::respond(['error' => 'Invalid credentials'], 401);
}

/**
 * @route GET /get-data
 * @tag Other Group
 * @desc Public GET endpoint with query params
 * @response 200 {"message":"This is public GET data","params":{"name":"value"}}
 */
function getGetData() {
    App::respond([
        'message' => 'This is public GET data',
        'params' => $_GET
    ]);
}

/**
 * @route POST /post-data
 * @desc Protected POST endpoint with JSON body
 * @auth true
 * @body {"key":"value"}
 * @response 200 {"received":{"key":"value"}}
 */
function postPostData() {
    $input = json_decode(file_get_contents('php://input'), true);
    App::respond(['received' => $input]);
}

/**
 * @route PUT /put-data
 * @desc Protected PUT endpoint with JSON update
 * @auth true
 * @body {"update":"info"}
 * @response 200 {"updated":{"update":"info"}}
 */
function putPutData() {
    $input = json_decode(file_get_contents('php://input'), true);
    App::respond(['updated' => $input]);
}

/**
 * @route PATCH /patch-data
 * @desc Protected PATCH endpoint with partial update
 * @auth true
 * @body {"patch":"value"}
 * @response 200 {"patched":{"patch":"value"}}
 */
function patchPatchData() {
    $input = json_decode(file_get_contents('php://input'), true);
    App::respond(['patched' => $input]);
}

/**
 * @route DELETE /delete-data/{id}
 * @desc Protected DELETE endpoint with URL param
 * @auth true
 * @response 200 {"deleted":true,"id":"value"}
 */
function deleteDeleteData() {
    $uriParts = explode('/', trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/'));
    $id = end($uriParts);
    App::respond(['deleted' => true, 'id' => $id]);
}

// ===================== CORE APP =====================

class App {
    private static array $env = [];

    /**
     * Executes the main application logic, routing HTTP requests to the appropriate
     * functions based on their annotations. Loads environment variables, parses the
     * request URI and method, and checks for documentation routes to serve OpenAPI
     * or Swagger documentation. Iterates through defined user functions to match 
     * the route and method, and invokes the function if it matches. Performs 
     * authorization checks for protected routes and responds with a 404 error if 
     * no route is matched.
     */
    public static function run() {
        self::loadEnv();

        $uri = rtrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
        $method = $_SERVER['REQUEST_METHOD'];

        if ($uri === '/docs') return self::serveDocs();
        if ($uri === '/openapi.json') return self::serveOpenAPI();

        foreach (get_defined_functions()['user'] as $fn) {
            $doc = (new \ReflectionFunction($fn))->getDocComment();
            if (!$doc) continue;

            preg_match('/@route\s+(GET|POST|PUT|PATCH|DELETE)\s+(\/[^\s]+)/', $doc, $route);
            preg_match('/@auth\s+(true|false)/', $doc, $auth);

            if ($route) {
                $routeMethod = strtoupper($route[1]);
                $routePath = rtrim($route[2], '/');
                $pattern = preg_replace('/\{[^\/]+\}/', '[^\/]+', $routePath);
                if ($routeMethod === $method && preg_match("#^{$pattern}$#", $uri)) {
                    if (($auth[1] ?? 'false') === 'true' && !self::isAuthorized()) return;
                    return call_user_func($fn);
                }
            }
        }

        self::respond(['error' => 'Not Found'], 404);
    }

    public static function loadEnv(string $file = '.env'): void {
        if (!file_exists($file)) return;
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (str_starts_with(trim($line), '#')) continue;
            [$name, $value] = explode('=', $line, 2);
            self::$env[trim($name)] = trim($value);
        }
    }

    public static function getEnv(string $key, string $default = ''): string {
        return self::$env[$key] ?? $default;
    }

    /**
     * Verifies the JWT token from the 'jwtauth' header in the request.
     * Checks the signature, structure, and expiration date of the token.
     * If any of these checks fail, it responds with a 401 error status.
     * If all checks pass, it returns true.
     */
    public static function isAuthorized(): bool {
        $headers = self::getAuthorizationHeaders();
        $jwt = $headers['jwtauth'] ?? null;
        if (!$jwt) self::respond(['error' => 'Missing jwtauth header'], 401);

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) self::respond(['error' => 'Invalid JWT structure'], 401);

        [$header, $payload, $signature] = $parts;
        $expected = self::b64url(self::hmac("$header.$payload"));
        if (!hash_equals($expected, $signature)) {
            self::respond(['error' => 'JWT signature mismatch'], 401);
        }

        $payloadData = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);
        if (!isset($payloadData['exp']) || time() > $payloadData['exp']) {
            self::respond(['error' => 'JWT token has expired'], 401);
        }

        return true;
    }

    /**
     * Gets the HTTP headers associated with the request, using the getallheaders
     * function if available, or falling back to the $_SERVER superglobal.
     * Returns an associative array of headers.
     * @return array
     */
    public static function getAuthorizationHeaders(): array {
        $headers = [];
        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                $headers[strtolower($name)] = $value;
            }
        }
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = str_replace('_', '-', strtolower(substr($key, 5)));
                $headers[$name] = $value;
            }
        }
        if (!isset($headers['jwtauth']) && isset($_SERVER['HTTP_JWTAUTH'])) {
            $headers['jwtauth'] = $_SERVER['HTTP_JWTAUTH'];
        }
        return $headers;
    }

    /**
     * Generates a SHA256 HMAC signature of the given data using the JWT_SECRET
     * environment variable, or 'fallback_secret' if not set.
     * @param string $data The data to sign
     * @return string The HMAC signature
     */
    public static function hmac($data): string {
        $secret = self::getEnv('JWT_SECRET', 'fallback_secret');
        return hash_hmac('sha256', $data, $secret, true);
    }

    /**
     * URL-safe base64 encode a string. This function is a wrapper around
     * base64_encode, but it replaces the + and / characters with - and _, and
     * trims the trailing = characters.
     * @param string $data The string to encode
     * @return string The URL-safe base64 encoded string
     */
    public static function b64url($data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Check if the DEBUG environment variable is set to true.
     * @return bool true if debug mode is enabled, false otherwise
     */
    public static function isDebug(): bool {
        return strtolower(self::getEnv('DEBUG', 'false')) === 'true';
    }
    
    /**
     * Outputs the given data as a response and exits. If the data is an error
     * and debug mode is enabled, it adds some debug information to the response.
     * It also respects the Accept header and outputs the response in the
     * requested format (application/json or application/xml).
     * @param mixed $data The data to output as a response
     * @param int $code The HTTP status code for the response
     */
    public static function respond($data, $code = 200): void {
        http_response_code($code);
        $accept = $_SERVER['HTTP_ACCEPT'] ?? 'application/json';
    
        // Automatically add debug info if enabled and response is error
        if (self::isDebug() && isset($data['error'])) {
            $data['_debug'] = [
                'method' => $_SERVER['REQUEST_METHOD'] ?? null,
                'uri' => $_SERVER['REQUEST_URI'] ?? null,
                'headers' => self::getAuthorizationHeaders(),
                'timestamp' => date('c')
            ];
        }
    
        if (stripos($accept, 'application/xml') !== false) {
            header('Content-Type: application/xml');
            echo self::toXML($data);
        } else {
            header('Content-Type: application/json');
            echo json_encode($data, self::isDebug() ? JSON_PRETTY_PRINT : 0);
        }
        exit;
    }

    /**
     * Recursively converts an array or object to XML.
     * @param mixed $data The data to convert to XML
     * @param string $root The root element of the XML document. Defaults to "response".
     * @return string The XML as a string
     */
    public static function toXML($data, $root = 'response'): string {
        $xml = new SimpleXMLElement("<?xml version=\"1.0\"?><$root/>");
        $add = function ($data, $xml) use (&$add) {
            foreach ($data as $key => $value) {
                if (is_array($value)) {
                    $sub = $xml->addChild(is_numeric($key) ? "item" : $key);
                    $add($value, $sub);
                } else {
                    $xml->addChild(is_numeric($key) ? "item" : $key, htmlspecialchars((string)$value));
                }
            }
        };
        $add($data, $xml);
        return $xml->asXML();
    }

    /**
     * Serves the Swagger UI documentation page. Sets the Content-Type header to text/html
     * and outputs the HTML content for Swagger UI, which loads the API specification from
     * /openapi.json and renders it using Swagger UI's bundle.
     */
    public static function serveDocs() {
        header('Content-Type: text/html');
        echo <<<HTML
<!DOCTYPE html>
<html>
<head>
  <title>Easy API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
</head>
<body>
<div id="root-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: '/openapi.json',
  dom_id: '#root-ui',
  layout: "BaseLayout"
});
</script>
</body>
</html>
HTML;
        exit;
    }

    /**
     * Generates and serves the OpenAPI 3.0 specification for the API as a JSON document.
     * It iterates through all user-defined functions and extracts information from their
     * PHPDoc comments. The information is then used to build the OpenAPI specification.
     * The specification is then outputted as a JSON document. The Content-Type header is
     * set to application/json.
     */
    public static function serveOpenAPI() {
        $paths = [];
        $tags = [];

        foreach (get_defined_functions()['user'] as $fn) {
            $doc = (new \ReflectionFunction($fn))->getDocComment();
            if (!$doc) continue;

            preg_match('/@route\s+(GET|POST|PUT|PATCH|DELETE)\s+(\/[^\s]+)/', $doc, $route);
            preg_match('/@desc\s+([^\n]+)/', $doc, $desc);
            preg_match('/@auth\s+(true|false)/', $doc, $auth);
            preg_match('/@body\s+([^\n]+)/', $doc, $body);
            preg_match('/@response\s+200\s+([^\n]+)/', $doc, $resp);
            preg_match('/@tag\s+([^\n]+)/', $doc, $tag);

            if ($route) {
                $method = strtolower($route[1]);
                $url = rtrim($route[2], '/');

                $tagName = $tag[1] ?? 'General';
                $tags[$tagName] = ['name' => $tagName];

                $paths[$url][$method] = [
                    'summary' => $desc[1] ?? '',
                    'tags' => [$tagName],
                    'security' => ($auth[1] ?? 'false') === 'true' ? [['jwtauth' => []]] : [],
                    'requestBody' => isset($body[1]) ? [
                        'required' => true,
                        'content' => [
                            'application/json' => [
                                'example' => json_decode($body[1], true)
                            ]
                        ]
                    ] : null,
                    'responses' => [
                        '200' => [
                            'description' => 'OK',
                            'content' => [
                                'application/json' => [
                                    'example' => isset($resp[1]) ? json_decode($resp[1], true) : ['message' => 'OK']
                                ],
                                'application/xml' => [
                                    'example' => ['message' => 'This is an XML example']
                                ]
                            ]
                        ]
                    ]
                ];
            }
        }

        $openapi = [
            'openapi' => '3.0.0',
            'info' => ['title' => 'Easy API', 'version' => '1.0.0'],
            'tags' => array_values($tags),
            'paths' => $paths,
            'components' => [
                'securitySchemes' => [
                    'jwtauth' => [
                        'type' => 'apiKey',
                        'in' => 'header',
                        'name' => 'jwtauth'
                    ]
                ]
            ]
        ];

        header('Content-Type: application/json');
        echo json_encode($openapi, JSON_PRETTY_PRINT);
        exit;
    }
}

App::run();
