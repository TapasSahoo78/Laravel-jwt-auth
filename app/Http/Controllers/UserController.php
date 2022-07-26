<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;
use Auth;

class UserController extends Controller
{
    public function register(Request $request)
    {
        //Validate data
        $data = $request->only('name', 'email', 'password', 'password_confirmation');
        $validator = Validator::make($data, [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|between:8,255|confirmed'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        //Request is valid, create new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        //User created, return success response
        return response()->json([
            'success' => true,
            'message' => 'User created successfully',
            'data' => $user
        ], Response::HTTP_OK);
    }

    //For Login
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|between:8,255'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        //Request is validated
        //Crean token
        try {
            if (!$token = auth()->attempt($validator->validated())) {
                return response()->json([
                    'success' => false,
                    'message' => 'Login credentials are invalid.',
                ], 400);
            }
        } catch (JWTException $th) {
            return response()->json([
                'success' => false,
                'message' => 'Could not create token.',
                'error' => $th
            ], 500);
        }

        //Crean token
        return $this->respondWithToken($token);
    }
    protected function respondWithToken($token)
    {
        return response()->json([
            'success' => true,
            'access_token' => $token,
            'token_type' => 'bearer',
            'expire_in' => auth()->factory()->getTTL() * 60
        ], 400);
    }

    public function profile()
    {
        return response()->json(auth()->user());
    }
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }
    public function logout()
    {
        auth()->logout();
        return response()->json([
            'message' => 'User successfully log out.',
        ], Response::HTTP_OK);
    }
}
