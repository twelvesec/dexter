<?php


namespace App\Http\Controllers\API;

use App\Http\Controllers\API\BaseController;
use Illuminate\Http\Request;
use App\Computer;
use Validator;

class ComputerController extends BaseController
{
    /*public function __construct()
    {
        parent::__construct();
    }*/

    public function index()
    {
        $computers = Computer::all();

        return $this->sendResponse($computers->toArray(), 'Computers retrieved successfully.');
    }

    public function store(Request $request)
    {
        $input = $request->all();

        $validator = Validator::make($input, [
            'uid' => 'required',
            'computername' => 'required',
            'os' => 'required',
            'username' => 'required',
            'localipaddress' => 'required',
            'physicaladdress' => 'required'
        ]);


        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());
        }

        $computer = Computer::create([
            'computername' => $request->computername,
            'os' => $request->os,
            'username' => $request->username,
            'user_id' => $request->user()->id
          ]);

        return $this->sendResponse($computer->toArray(), 'Computer created successfully.');
    }

    /*public function update(Request $request, Computer $computer)
    {
        if ($request->user()->id !== $computer->user_id) {
            return response()->json(['error' => 'You can only edit your own computers.'], 403);
        }

        $input = $request->all();

        $validator = Validator::make($input, [
            'uid' => 'required',
            'computername' => 'required',
            'os' => 'required',
            'username' => 'required',
            'localipaddress' => 'required',
            'physicaladdress' => 'required'
        ]);


        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());
        }

        $computer->update($request->only(['computername', 'os', 'username']));

        return $this->sendResponse($computer->toArray(), 'Computer updated successfully.');
    }*/
}
