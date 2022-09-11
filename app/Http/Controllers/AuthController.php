<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Traits\ApiResponser;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

/** @package App\Http\Controllers */
class AuthController extends Controller
{

    use ApiResponser;

    public function isRegisterValid(Request $request)
    {
        return  $this->validate(
            $request,
            [
                'name' => 'required',
                'email' => 'required|email|unique:users',
                'password' => 'required|min:5'
            ]
        );
    }

    private function isLoginEmailValid(Request $request)
    {
        return $this->validate($request, [
            'email' => 'required|string',
            'password' =>  'required|string'
        ]);
    }

    private function isLoginCredentiallValid(Request $request)
    {

        return $this->validate($request, [
            'client_id' => 'required|string',
            'client_secret' =>  'required|string'
        ]);
    }

    private function loginWithCredential(Request $request)
    {
        if ($this->isLoginCredentiallValid($request)) {
            $credentials = $request->only(['client_id', 'client_secret']);
            $user =  User::where('client_id', $request->client_id)->where('client_secret', $request->client_secret)->first();
            if($user){
                $token = auth()->setTTL(env('JWT_TTL', '60'))->login($user);
                return $token;
            }else{
                return null;
            }

        }
    }

    private function returnUserWithToken($token)
    {
        return [
            "token" => [
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL()
        ],
        "user" => auth()->user()
        ];
    }

    private function generateApiKey()
    {
        $data = random_bytes(16);
        if (false === $data) {
            return false;
        }
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    private function loginWithEmail(Request $request)
    {

        if ($this->isLoginEmailValid($request)) {
            $credentials = $request->only(['email', 'password']);
            $token = auth()->setTTL(env('JWT_TTL', '60'))->attempt($credentials);
            return $token;
        }
    }

    public function login(Request $request)
    {
        if (isset($request->grant_type)) {
            if ($request->grant_type == 'credential') {
                $token = $this->loginWithCredential($request);
            } else {
                $token = $this->loginWithEmail($request);
            }
        } else {
            $token = $this->loginWithEmail($request);
        }

        if ($token) {
            return $this-> returnUserWithToken($token);
        } else {
            return $this->errorResponse('user not found', Response::HTTP_NOT_FOUND);
        }
    }

    public function register(Request $request)
    {

        if ($this->isRegisterValid($request)) {
            try {
                $user = new User();
                $user->password = $request->password;
                $user->email = $request->email;
                $user->name = $request->name;
                $user->avatar_url = $request->avatar_url;
                $user->nickname = $request->nickname;
                $user->provider = $request->provider;
                $user->id_social = $request->id_social;
                $user->client_id = $this->generateApiKey();
                $user->client_secret = $this->generateApiKey();

                if ($user->save()) {
                    $token = $this->loginWithEmail($request);
                    $newUser = $this->returnUserWithToken($token);
                    return $this->successResponse($newUser);
                }
            } catch (\Exception $e) {
                return $this->errorResponse($e->getMessage(), Response::HTTP_BAD_REQUEST);
            }
        }
    }

    public function profile($id){

        $user = User::where('id',$id)->first();

        if($user) {
            return $this->successResponse($user);
        }

        return $this->successResponse("user not found");
    }

}
