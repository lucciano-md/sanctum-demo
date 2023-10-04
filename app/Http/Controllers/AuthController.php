<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function sign_up(Request $request){
	$data = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
	    'password' => 'required|string|confirmed',
	    'password_confirmation' => 'required|string|confirmed',
        ]);

	$user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);

	$token = $user->createToken('apiToken')->plainTextToken;
	$res = [
            'user' => $user,
            'token' => $token
        ];
        return response($res, 201);
    }

    public function sign_in(Request $request){
	$data = $request->validate([
            'email' => 'required|string|email',
	    'password' => 'required|string',
        ]);

	$user = User::where('email', $data['email'])->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
           return response(['message' => 'Unauthenticated.'], 401);
        }

	$token = $user->createToken('apiToken')->plainTextToken;
	$res = [
            'user' => $user,
            'token' => $token
        ];
        return response($res, 201);
    }
}
