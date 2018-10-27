<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddIndices extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('computers', function (Blueprint $table) {
            $table->index('uid');
            $table->index('computername');
            $table->index('os');
            $table->index('username');
            $table->index('localipaddress');
            $table->index('physicaladdress');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('computers', function (Blueprint $table) {
            $table->dropIndex('uid');
            $table->dropIndex('computername');
            $table->dropIndex('os');
            $table->dropIndex('username');
            $table->dropIndex('localipaddress');
            $table->dropIndex('physicaladdress');
        });
    }
}
