// Package email provides HTML email templates for ModernAuth.
package email

// Default theme colors - can be overridden via branding settings
const (
	DefaultPrimaryColor    = "#2B2B2B" // Dark - headers, buttons
	DefaultSecondaryColor  = "#B3B3B3" // Medium gray - accents
	DefaultBackgroundColor = "#FFFFFF" // White - content background
	DefaultBorderColor     = "#D4D4D4" // Light gray - borders
	DefaultTextPrimary     = "#2B2B2B" // Dark - primary text
	DefaultTextSecondary   = "#B3B3B3" // Medium gray - secondary text
	DefaultTextMuted       = "#D4D4D4" // Light gray - footer text
)

// Email HTML templates with inline styles for better email client compatibility.
// Templates use Go template variables for dynamic theming:
// - {{.PrimaryColor}} - Header background, buttons (default: #2B2B2B)
// - {{.SecondaryColor}} - Accents, highlights (default: #B3B3B3)
// Additional standard colors used:
// - #FFFFFF - Content background
// - #D4D4D4 - Borders, muted text
// - #B3B3B3 - Secondary text
// - #2B2B2B - Primary text

const verificationEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Verify Your Email</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.VerifyURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email</a>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="color: #B3B3B3; font-size: 12px; word-break: break-all; background: #F5F5F5; padding: 10px; border-radius: 5px;">{{.VerifyURL}}</p>
        <p style="color: #B3B3B3; font-size: 14px;">If you didn't create an account, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const passwordResetEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Reset Your Password</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>You requested to reset your password. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.ResetURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="color: #B3B3B3; font-size: 12px; word-break: break-all; background: #F5F5F5; padding: 10px; border-radius: 5px;">{{.ResetURL}}</p>
        <p style="color: {{.SecondaryColor}}; font-size: 14px;"><strong>Note: This link will expire in 1 hour.</strong></p>
        <p style="color: #B3B3B3; font-size: 14px;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const welcomeEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Welcome to {{.AppName}}</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Welcome aboard! Your account has been created successfully.</p>
        <p>Here are some things you can do:</p>
        <ul style="color: #B3B3B3;">
            <li>Set up two-factor authentication for extra security</li>
            <li>Complete your profile</li>
            <li>Explore our features</li>
        </ul>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.BaseURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Get Started</a>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">If you have any questions, feel free to reach out to our support team.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const loginAlertEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">New Login Detected</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>We noticed a new login to your account from a device we don't recognize:</p>
        <div style="background: #F5F5F5; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <table style="width: 100%; font-size: 14px;">
                <tr>
                    <td style="padding: 5px 0; color: #B3B3B3;"><strong>Device:</strong></td>
                    <td style="padding: 5px 0;">{{.DeviceName}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #B3B3B3;"><strong>Browser:</strong></td>
                    <td style="padding: 5px 0;">{{.Browser}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #B3B3B3;"><strong>OS:</strong></td>
                    <td style="padding: 5px 0;">{{.OS}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #B3B3B3;"><strong>IP Address:</strong></td>
                    <td style="padding: 5px 0;">{{.IPAddress}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #B3B3B3;"><strong>Location:</strong></td>
                    <td style="padding: 5px 0;">{{.Location}}</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #B3B3B3;"><strong>Time:</strong></td>
                    <td style="padding: 5px 0;">{{.Time}}</td>
                </tr>
            </table>
        </div>
        <p><strong>Was this you?</strong></p>
        <p style="color: #B3B3B3; font-size: 14px;">If this was you, you can safely ignore this email.</p>
        <p style="color: {{.SecondaryColor}}; font-size: 14px;"><strong>If this wasn't you:</strong> Please change your password immediately and enable two-factor authentication to secure your account.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const invitationEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">You're Invited</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi there,</p>
        <p><strong>{{.InviterName}}</strong> has invited you to join <strong>{{.TenantName}}</strong>.</p>
        {{if .Message}}
        <div style="background: #F5F5F5; padding: 15px; border-left: 4px solid {{.PrimaryColor}}; margin: 20px 0; font-style: italic;">
            "{{.Message}}"
        </div>
        {{end}}
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.InviteURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Accept Invitation</a>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="color: #B3B3B3; font-size: 12px; word-break: break-all; background: #F5F5F5; padding: 10px; border-radius: 5px;">{{.InviteURL}}</p>
        <p style="color: {{.SecondaryColor}}; font-size: 14px;"><strong>Note: This invitation expires on {{.ExpiresAt}}.</strong></p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const mfaEnabledEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Two-Factor Authentication Enabled</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Two-factor authentication has been <strong>enabled</strong> on your account. Your account is now more secure!</p>
        <p style="color: #B3B3B3; font-size: 14px;">From now on, you'll need to enter a verification code from your authenticator app when logging in.</p>
        <div style="background: #FFF9E6; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid {{.SecondaryColor}};">
            <p style="margin: 0; color: #2B2B2B;"><strong>Important:</strong> Make sure to save your backup codes in a secure place. You'll need them if you lose access to your authenticator app.</p>
        </div>
        <p style="color: {{.SecondaryColor}}; font-size: 14px;"><strong>If you didn't enable 2FA:</strong> Please contact support immediately as your account may have been compromised.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const mfaCodeEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Your Verification Code</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi,</p>
        <p>Use the following verification code to complete your login:</p>
        <div style="background: #F5F5F5; padding: 25px; border-radius: 10px; margin: 25px 0; text-align: center; border: 2px dashed {{.PrimaryColor}};">
            <p style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: {{.PrimaryColor}}; margin: 0;">{{.MFACode}}</p>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">This code will expire in 10 minutes.</p>
        <p style="color: {{.SecondaryColor}}; font-size: 14px;"><strong>Security Note:</strong> If you didn't request this code, please ignore this email or contact support if you're concerned.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const lowBackupCodesEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Action Required</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>You have only <strong>{{.Remaining}} backup codes remaining</strong> for two-factor authentication.</p>
        <div style="background: #FFF9E6; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid {{.SecondaryColor}};">
            <p style="margin: 0; color: #2B2B2B;"><strong>Why this matters:</strong><br>
            Backup codes are your safety net if you lose access to your authenticator app or device. Once you use all your backup codes, you may be locked out of your account.</p>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;"><strong>What you should do:</strong></p>
        <ul style="color: #B3B3B3;">
            <li>Go to your account security settings</li>
            <li>Generate a new set of backup codes</li>
            <li>Store them in a secure location (password manager, safe, etc.)</li>
        </ul>
        <p style="color: {{.SecondaryColor}}; font-size: 14px;"><strong>Note:</strong> Generating new backup codes will invalidate your existing ones.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const passwordChangedEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Password Changed</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Your password has been successfully changed.</p>
        <p style="color: #B3B3B3; font-size: 14px;">If you made this change, no further action is needed.</p>
        <div style="background: #FFEFEF; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid {{.SecondaryColor}};">
            <p style="margin: 0; color: #2B2B2B;"><strong>Didn't change your password?</strong> If you didn't make this change, please reset your password immediately and contact support. Your account may have been compromised.</p>
        </div>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const sessionRevokedEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Session Terminated</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>One or more of your sessions has been terminated.</p>
        <div style="background: #F5F5F5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #B3B3B3;"><strong>Reason:</strong> {{.Reason}}</p>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">If you did this intentionally (e.g., logged out from another device or revoked all sessions), no further action is needed.</p>
        <p style="color: {{.SecondaryColor}}; font-size: 14px;"><strong>If you didn't do this:</strong> Please change your password immediately as your account may have been compromised.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const accountDeactivatedEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Account Deactivated</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Your account has been deactivated.</p>
        {{if .Reason}}
        <div style="background: #F5F5F5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #B3B3B3;"><strong>Reason:</strong> {{.Reason}}</p>
        </div>
        {{end}}
        {{if .ReactivationURL}}
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.ReactivationURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reactivate Account</a>
        </div>
        {{end}}
        <p style="color: #B3B3B3; font-size: 14px;">If you believe this was a mistake, please contact our support team.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const emailChangedEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Email Address Changed</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>The email address associated with your account has been changed from <strong>{{.OldEmail}}</strong> to <strong>{{.NewEmail}}</strong>.</p>
        <div style="background: #FFF9E6; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid {{.SecondaryColor}};">
            <p style="margin: 0; color: #2B2B2B;"><strong>Didn't make this change?</strong> If you didn't authorize this change, please contact our support team immediately and consider changing your password.</p>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">If you made this change, no further action is needed.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const passwordExpiryEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Password Expiring Soon</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>Your password will expire in <strong>{{.DaysUntilExpiry}} days</strong> on {{.ExpiryDate}}.</p>
        <p style="color: #B3B3B3; font-size: 14px;">To avoid any disruption to your access, please update your password before it expires.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.ChangePasswordURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Change Password</a>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">If you didn't request this change, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const securityAlertEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Security Alert</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p><strong>{{.AlertTitle}}</strong></p>
        <div style="background: #F5F5F5; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0 0 10px 0;">{{.AlertMessage}}</p>
            {{if .AlertDetails}}
            <p style="margin: 0; color: #B3B3B3; font-size: 14px;">{{.AlertDetails}}</p>
            {{end}}
        </div>
        {{if .ActionURL}}
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.ActionURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">{{.ActionText}}</a>
        </div>
        {{end}}
        <p style="color: #B3B3B3; font-size: 14px;">If you have any questions about this alert, please contact our support team.</p>
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const rateLimitWarningEmailHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2B2B2B; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: {{.PrimaryColor}}; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: #FFFFFF; margin: 0; font-size: 24px;">Rate Limit Approaching</h1>
    </div>
    <div style="background: #FFFFFF; padding: 30px; border: 1px solid #D4D4D4; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Hi {{.FullName}},</p>
        <p>You're approaching the rate limit for <strong>{{.ActionType}}</strong> actions on your account.</p>
        <div style="background: #F5F5F5; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0 0 5px 0;"><strong>Current Usage:</strong> {{.CurrentCount}} / {{.MaxCount}}</p>
            <p style="margin: 0; color: #B3B3B3; font-size: 14px;">{{.TimeWindow}}</p>
        </div>
        <p style="color: #B3B3B3; font-size: 14px;">To avoid being blocked, please reduce the frequency of this action or contact us to increase your limits.</p>
        {{if .UpgradeURL}}
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.UpgradeURL}}" style="background: {{.PrimaryColor}}; color: #FFFFFF; padding: 14px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Upgrade Plan</a>
        </div>
        {{end}}
        <hr style="border: none; border-top: 1px solid #D4D4D4; margin: 30px 0;">
        <p style="color: #D4D4D4; font-size: 12px; text-align: center;">{{.FooterText}}</p>
    </div>
</body>
</html>`

const TrackingPixel = `<img src="{{.BaseURL}}/api/email/track/{{.Email}}/{{.TemplateType}}/{{.EventID}}" width="1" height="1" alt="" style="display:none;" />`
