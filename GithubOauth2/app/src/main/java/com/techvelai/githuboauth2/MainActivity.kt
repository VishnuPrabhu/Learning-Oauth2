package com.techvelai.githuboauth2

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.auth0.android.jwt.JWT
import com.techvelai.githuboauth2.ui.theme.GithubOauth2Theme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.openid.appauth.AppAuthConfiguration
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.EndSessionRequest
import net.openid.appauth.ResponseTypeValues
import net.openid.appauth.browser.BrowserAllowList
import net.openid.appauth.browser.VersionedBrowserMatcher
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.IllegalStateException

class MainActivity : ComponentActivity() {

    private var authState: AuthState = AuthState()
    private var jwt: JWT? = null
    private lateinit var authorizationService: AuthorizationService
    private lateinit var authorizationServiceConfig: AuthorizationServiceConfiguration


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        initAuthServiceConfig()
        initAuthService()
        restoreState()
        setContent {
            GithubOauth2Theme {
                // A surface container using the 'background' color from the theme
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column {
                        Row {
                            Button(onClick = {
                                attemptAuthorization()
                            }) {
                                Text("Log In!")
                            }
                            Spacer(Modifier.width(16.dp))
                            Button(onClick = {
                                signOutWithoutRedirect()
                            }) {
                                Text("Sign Out!")
                            }
                        }
                        Spacer(Modifier.height(16.dp))
                        Button(onClick = {
                            makeApi()
                        }) {
                            Text("Fetch Data!")
                        }
                    }

                }
            }
        }
    }

    fun restoreState() {
        val jsonString = applicationContext
            .getSharedPreferences(Constants.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
            .getString(Constants.AUTH_STATE, null)
        jsonString.let {
            try {
                if (!it.isNullOrEmpty()) {
                    authState = AuthState.jsonDeserialize(it)
                }

                if (!authState.idToken.isNullOrEmpty()) {
                    jwt = JWT(authState.idToken!!)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    fun saveState() {
        applicationContext
            .getSharedPreferences(Constants.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(Constants.AUTH_STATE, authState.jsonSerializeString())
            .commit()
    }

    private fun deleteState() {
        applicationContext
            .getSharedPreferences(Constants.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(Constants.AUTH_STATE, null)
            .commit()
        authState = AuthState()
    }

    private fun initAuthServiceConfig() {
        authorizationServiceConfig = AuthorizationServiceConfiguration(
            Uri.parse(Constants.URL_AUTHORIZATION),
            Uri.parse(Constants.URL_TOKEN_EXCHANGE),
            null,
            Uri.parse(Constants.URL_LOGOUT)
        )
    }

    private fun initAuthService() {
        val appAuthConfiguration = AppAuthConfiguration.Builder()
            .setBrowserMatcher(
                BrowserAllowList(
                    VersionedBrowserMatcher.CHROME_CUSTOM_TAB,
                    VersionedBrowserMatcher.SAMSUNG_CUSTOM_TAB
                )
            ).build()
        authorizationService = AuthorizationService(
            applicationContext,
            appAuthConfiguration
        )
    }

    private fun attemptAuthorization() {
        val secureRandom = SecureRandom()
        val bytes = ByteArray(64)
        secureRandom.nextBytes(bytes)

        val encoding = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        val codeVerifier = Base64.encodeToString(bytes, encoding)

        val digest = MessageDigest.getInstance(Constants.MESSAGE_DIGEST_ALGORITHM)
        val hash = digest.digest(codeVerifier.toByteArray())
        val codeChallenge = Base64.encodeToString(hash, encoding)

        val request = AuthorizationRequest.Builder(
            authorizationServiceConfig,
            Constants.CLIENT_ID,
            ResponseTypeValues.CODE,
            Uri.parse(Constants.URL_AUTH_REDIRECT)
        ).apply {
            setCodeVerifier(codeVerifier, codeChallenge, Constants.CODE_VERIFIER_CHALLENGE_METHOD)
            setScopes(Constants.SCOPE_PROFILE, Constants.SCOPE_EMAIL, Constants.SCOPE_OPENID, Constants.SCOPE_DRIVE)
        }.build()

        val authIntent = authorizationService.getAuthorizationRequestIntent(request)
        launchForResult(authIntent)
    }


    private val authorizationLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            run {
                if (result.resultCode == Activity.RESULT_OK) {
                    handleAuthorizationResponse(result.data!!)
                }
            }
        }

    private fun launchForResult(authIntent: Intent?) {
        authorizationLauncher.launch(authIntent)
    }

    private fun handleAuthorizationResponse(data: Intent) {
        val authorizationResponse: AuthorizationResponse? = AuthorizationResponse.fromIntent(data)
        val error: AuthorizationException? = AuthorizationException.fromIntent(data)

        authState = AuthState(authorizationResponse, error)

        val tokenExchangeRequest = authorizationResponse?.createTokenExchangeRequest()
        authorizationService.performTokenRequest(tokenExchangeRequest!!) { response, exception ->
            if (exception != null) {
                authState = AuthState()
            } else {
                authState.update(response, exception)
                jwt = JWT(authState.idToken!!)

                val userFirstName = jwt?.getClaim(Constants.DATA_FIRST_NAME)?.asString()
                val userLastName = jwt?.getClaim(Constants.DATA_LAST_NAME)?.asString()
                val userEmail = jwt?.getClaim(Constants.DATA_EMAIL)?.asString()
                val userPicture = jwt?.getClaim(Constants.DATA_PICTURE)
            }
            saveState()
        }
    }

    fun makeApi() {
        authState.performActionWithFreshTokens(authorizationService, object : AuthState.AuthStateAction {
            override fun execute(accessToken: String?, idToken: String?, ex: AuthorizationException?) {
                this@MainActivity.lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        val client = OkHttpClient()
                        val request = Request.Builder()
                            .url(Constants.URL_API_CALL)
                            .addHeader("Authorization", "Bearer " + authState.accessToken)
                            .build()
                        try {
                            val response = client.newCall(request).execute()
                            val jsonBody = response.body?.string() ?: ""
                            Log.i(Constants.LOG_TAG, JSONObject(jsonBody).toString())
                        } catch (e: Exception) {
                            e.printStackTrace()
                        }
                    }
                }
            }
        })
    }

    private fun signOut() {
        try {
            val endSessionRequest = EndSessionRequest.Builder(authorizationServiceConfig)
                .setPostLogoutRedirectUri(Uri.parse(Constants.URL_LOGOUT_REDIRECT))
                .setIdTokenHint(authState.accessToken)
                .build()

            val signOutIntent = authorizationService.getEndSessionRequestIntent(endSessionRequest)
            launchForResult(signOutIntent)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun signOutWithoutRedirect() {
        val client = OkHttpClient()
        val request = Request.Builder()
            .post("".toRequestBody())
            .header("Content-type", "application/x-www-form-urlencoded")
            .url(Constants.URL_LOGOUT + authState.accessToken)
            .build()

        try {
            lifecycleScope.launch {
                withContext(Dispatchers.IO) {
                    val result = client.newCall(request).execute()
                    if (result.code == 200) {
                        deleteState()
                    } else {
                        throw IllegalStateException(result.body?.string())
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
