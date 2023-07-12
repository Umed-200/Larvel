<?php

namespace App\Http\Controllers;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    //

    public function register(RegisterRequest $request){

        $user = User::create([
            'name' => ['name'],
            'email' => ['email'],
            'password' => bcrypt(['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(LoginRequest $request){
        $fields = $request->validate();

        $user = User::where('email', $fields['email'])->first();


        if (!$user || !Hash::check($fields['password'],$user->password)){
            return response([
                'message' => 'bad creds'
            ], 401);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }




    public function logout(Request $request){
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Loged out'
        ];
    }
}
