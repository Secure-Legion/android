package com.example.securelegion

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.animation.Animation
import android.view.animation.AnimationUtils
import androidx.appcompat.app.AppCompatActivity

class SplashActivity : AppCompatActivity() {

    private val SPLASH_DELAY = 2000L // 2 seconds

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        // Animate logo
        val logo = findViewById<View>(R.id.splashLogo)
        val appName = findViewById<View>(R.id.appName)

        // Scale and fade in animation for logo
        logo.alpha = 0f
        logo.scaleX = 0.5f
        logo.scaleY = 0.5f
        logo.animate()
            .alpha(1f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(800)
            .setInterpolator(android.view.animation.OvershootInterpolator())
            .start()

        // Fade in app name
        appName.alpha = 0f
        appName.animate()
            .alpha(1f)
            .setDuration(600)
            .setStartDelay(400)
            .start()

        // Navigate to Lock screen after delay
        Handler(Looper.getMainLooper()).postDelayed({
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
            overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
        }, SPLASH_DELAY)
    }
}
