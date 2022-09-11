<?php

namespace App\Http\Middleware;

class CorsMiddleware
{
    public function handle($request, \Closure $next)
    {
        // if ($request->isMethod('OPTIONS')) {
        //     $response = response($response, 200);
        // } else {
        //     $response = $next($request);
        // }

        $response = $next($request);
        $response->header('Content-Type', 'application/json');
        $response->header('Access-Control-Max-Age', '86400');
        $response->header('Access-Control-Allow-Origin', '*');
        //$response->header('Access-Control-Allow-Credentials', 'true');

        $response->header('Access-Control-Allow-Origin','*');
        $response->header('Access-Control-Allow-Methods','*');
        $response->header('Access-Control-Allow-Headers','*');

        //$response->header('Access-Control-Allow-Headers', $request->header('Access-Control-Request-Headers'));
        $response->header('Access-Control-Allow-Methods', 'OPTIONS , HEAD , GET , POST , PUT , PATCH , DELETE ');

        return $response;
    }
}
