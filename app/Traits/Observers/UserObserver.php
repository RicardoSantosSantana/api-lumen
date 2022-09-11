<?php
namespace App\Traits\Observers;
use App\Models\User;
use Illuminate\Support\Facades\Mail;
trait UserObserver
{
    protected static function boot()
    {

        parent::boot();

        static::created(function (User $user) {

            $text = "Welcome to our website API\n";
            $text .= "This is your credentials\n";
            $text .= "Your Client ID : '{$user->client_id}'\n";
            $text .= "Your Client SECRET : '{$user->client_secret}'\n";
            $text .= "Grant Type : 'credential'\n";
            $text .= "You are now able to use our services!'\n";
            // send to mailtrap
            Mail::raw($text, function ($message) use ($user) {
                $message->from(env('MAIL_FROM_EMAIL','noreply@noreply.com'), env('MAIL_FROM_NAME','no-reply'));
                $message->subject("Welcome {$user->name}");
                $message->to($user->email);
            });
        });

    }
}
