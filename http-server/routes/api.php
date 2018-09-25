<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

/*Route::post('computers', function(Request $request) {
    return Computer::create($request->all);
});

Route::put('computers/{id}', function(Request $request, $id) {
    $computer = Computer::findOrFail($id);
    $computer->update($request->all());

    return $computer;
});*/

Route::middleware('auth:api')->group( function () {
    Route::resource('computers', 'api\ComputerController');
});
