<?php

namespace App\Http\Middleware;

use App\Traits\ApiResponser;
use Closure;
use Illuminate\Contracts\Auth\Factory as Auth;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
class Authenticate
{
     use ApiResponser;
    /**
     * The authentication guard factory instance.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @return void
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {

        if ($this->auth->guard($guard)->guest()) {
            try{

               //$token =  auth()->payload();
               return response()->json([
                'error'=>'not authorized',
                'message'=>'please provide valid token'
            ], 401);


            }catch(\Exception $e){
                if($e instanceof TokenInvalidException){
                    return $this->errorResponse($e->getMessage(), Response::HTTP_NOT_FOUND);
                }

                if($e instanceof TokenExpiredException){
                    return $this->errorResponse($e->getMessage(), Response::HTTP_UNAUTHORIZED);
                }

            }
        }

        return $next($request);
    }
}
