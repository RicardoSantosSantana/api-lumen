<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Traits\ApiResponser;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use stdClass;

/** @package App\Http\Controllers */
class AuthController extends Controller
{

    use ApiResponser;

    public function isRegisterValid(Request $request)
    {
        $rules =     [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:5'
        ];
        $message = [
            'name.required' => 'name is required',
            'email.required' => 'email is required',
            'email.email' => 'email is not valid',
            'email.unique' => 'this email has already been taken',
            'password.required' => 'password is required',
            'password.min' => 'password min 5 caracters'
        ];

        return Validator::make($request->all(), $rules, $message);
    }

    private function isLoginEmailValid(Request $request)
    {

        $rules =     [
            'email' => 'required|email',
            'password' => 'required'
        ];
        $message = [
            'email.required' => 'email is required',
            'email.email' => 'email is not valid',
            'password.required' => 'password is required'
        ];

        return Validator::make($request->all(), $rules, $message);
    }

    private function isLoginCredentiallValid(Request $request)
    {

        $rules =     [
            'client_id' => 'required|string',
            'client_secret' => 'required|string'
        ];

        $message = [
            'client_id.required' => 'client id is required',
            'client_id.string' => 'client id must be string',
            'client_secret.required' => 'client secret is required',
            'client_secret.string' => 'client secret must be string'
        ];

        return Validator::make($request->all(), $rules, $message);
    }

    private function loginWithCredential(Request $request)
    {

        $validator = $this->isLoginCredentiallValid($request);

        if ($validator->fails()) {
            $return = new stdClass;
            $return->error = $validator->errors();
            return  $return;
        }

        $credentials = $request->only(['client_id', 'client_secret']);
        $user =  User::where('client_id', $request->client_id)->where('client_secret', $request->client_secret)->first();
        if ($user) {
            $token = auth()->setTTL(env('JWT_TTL', '60'))->login($user);
            return $token;
        } else {
            return null;
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
        $validator = $this->isLoginEmailValid($request);

        if ($validator->fails()) {
            $return = new stdClass;
            $return->error = $validator->errors();
            return  $return;
        }

        $credentials = $request->only(['email', 'password']);
        $token = auth()->setTTL(env('JWT_TTL', '60'))->attempt($credentials);
        return $token;
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

        if (isset($token->error)) {
            return $this->errorResponse($token->error, 422);
        }

        if ($token) {
            return $this->returnUserWithToken($token);
        } else {
            return $this->errorResponse('user not found', Response::HTTP_NOT_FOUND);
        }
    }

    public function register(Request $request)
    {

        $validator = $this->isRegisterValid($request);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }


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

    public function profile($id)
    {

        $user = User::where('id', $id)->first();

        if ($user) {
            return $this->successResponse($user);
        }

        return $this->successResponse("user not found");
    }
}
