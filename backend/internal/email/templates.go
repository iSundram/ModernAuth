// Package email provides HTML email templates for ModernAuth.
package email

// Email HTML templates with inline styles for better email client compatibility.

const verificationEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Verify Your Email</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.VerifyURL}}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email</a>
        </div>
        <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="color: #666; font-size: 12px; word-break: break-all; background: #f5f5f5; padding: 10px; border-radius: 5px;">{{.VerifyURL}}</p>
        <p style="color: #666; font-size: 14px;">If you didn't create an account, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const passwordResetEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Reset Your Password</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>You requested to reset your password. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.ResetURL}}" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="color: #666; font-size: 12px; word-break: break-all; background: #f5f5f5; padding: 10px; border-radius: 5px;">{{.ResetURL}}</p>
        <p style="color: #e74c3c; font-size: 14px;"><strong>Note: This link will expire in 1 hour.</strong></p>
        <p style="color: #666; font-size: 14px;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const welcomeEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Welcome to {{.AppName}}</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Welcome aboard! Your account has been created successfully.</p>
        <p>Here are some things you can do:</p>
        <ul style="color: #666;">
            <li>Set up two-factor authentication for extra security</li>
            <li>Complete your profile</li>
            <li>Explore our features</li>
        </ul>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.BaseURL}}" style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Get Started</a>
        </div>
        <p style="color: #666; font-size: 14px;">If you have any questions, feel free to reach out to our support team.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const loginAlertEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #f39c12 0%, #e74c3c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">New Login Detected</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>We noticed a new login to your account from a device we don't recognize:</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <table style="width: 100%; font-size: 14px;">
                <tr>
                    <td style="padding: 5px 0; color: #666;"><strong>Device:</strong></td>
                    <td style="padding: 5px 0;">{{.DeviceName}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #666;"><strong>Browser:</strong></td>
                    <td style="padding: 5px 0;">{{.Browser}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #666;"><strong>OS:</strong></td>
                    <td style="padding: 5px 0;">{{.OS}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #666;"><strong>IP Address:</strong></td>
                    <td style="padding: 5px 0;">{{.IPAddress}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #666;"><strong>Location:</strong></td>
                    <td style="padding: 5px 0;">{{.Location}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #666;"><strong>Time:</strong></td>
                    <td style="padding: 5px 0;">{{.Time}}</td>
                </tr>
            </table>
        </div>
        <p><strong>Was this you?</strong></p>
        <p style="color: #666; font-size: 14px;">If this was you, you can safely ignore this email.</p>
        <p style="color: #e74c3c; font-size: 14px;"><strong>If this wasn't you:</strong> Please change your password immediately and enable two-factor authentication to secure your account.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const invitationEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">You're Invited</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi there,</p>
        <p><strong>{{.InviterName}}</strong> has invited you to join <strong>{{.TenantName}}</strong>.</p>
        {{if .Message}}
        <div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #667eea; margin: 20px 0; font-style: italic;">
            "{{.Message}}"
        </div>
        {{end}}
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.InviteURL}}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Accept Invitation</a>
        </div>
        <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="color: #666; font-size: 12px; word-break: break-all; background: #f5f5f5; padding: 10px; border-radius: 5px;">{{.InviteURL}}</p>
        <p style="color: #e74c3c; font-size: 14px;"><strong>Note: This invitation expires on {{.ExpiresAt}}.</strong></p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const mfaEnabledEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Two-Factor Authentication Enabled</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Two-factor authentication has been <strong>enabled</strong> on your account. Your account is now more secure!</p>
        <p style="color: #666; font-size: 14px;">From now on, you'll need to enter a verification code from your authenticator app when logging in.</p>
        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #856404;"><strong>Important:</strong> Make sure to save your backup codes in a secure place. You'll need them if you lose access to your authenticator app.</p>
        </div>
        <p style="color: #e74c3c; font-size: 14px;"><strong>If you didn't enable 2FA:</strong> Please contact support immediately as your account may have been compromised.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const passwordChangedEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Password Changed</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Your password has been successfully changed.</p>
        <p style="color: #666; font-size: 14px;">If you made this change, no further action is needed.</p>
        <div style="background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #721c24;"><strong>Didn't change your password?</strong> If you didn't make this change, please reset your password immediately and contact support. Your account may have been compromised.</p>
        </div>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const sessionRevokedEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #f39c12 0%, #e74c3c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Session Terminated</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>One or more of your sessions has been terminated.</p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #666;"><strong>Reason:</strong> {{.Reason}}</p>
        </div>
        <p style="color: #666; font-size: 14px;">If you did this intentionally (e.g., logged out from another device or revoked all sessions), no further action is needed.</p>
        <p style="color: #e74c3c; font-size: 14px;"><strong>If you didn't do this:</strong> Please change your password immediately as your account may have been compromised.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`
