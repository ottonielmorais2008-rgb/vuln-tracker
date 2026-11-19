import { useState, type FormEvent } from 'react'

type Props = {
  configured: boolean
  email: string | null
  isAnonymous: boolean
  busy: boolean
  onSignIn(email: string, password: string): Promise<void>
  onSignUp(email: string, password: string): Promise<void>
  onGuest(): Promise<void>
  onSignOut(): Promise<void>
}

export function AuthPanel({
  configured,
  email,
  isAnonymous,
  busy,
  onSignIn,
  onSignUp,
  onGuest,
  onSignOut,
}: Props) {
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [address, setAddress] = useState('')
  const [password, setPassword] = useState('')
  const signedIn = Boolean(email) || isAnonymous

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (mode === 'signup') await onSignUp(address, password)
    else await onSignIn(address, password)
    setPassword('')
    setOpen(false)
  }

  return (
    <aside className="auth">
      <div className="mode">
        <span className={`mode-dot${signedIn ? '' : ' demo'}`} />
        {signedIn
          ? isAnonymous
            ? 'Cloud storage · guest session'
            : `Cloud storage · ${email}`
          : 'Demo mode · data stays in this browser'}
      </div>
      <p>
        {configured
          ? signedIn
            ? 'Row Level Security keeps each signed-in user to their own findings.'
            : 'Sign in to save findings in the cloud, or keep using the local demo.'
          : 'Supabase is not configured, so the app is using local browser storage.'}
      </p>
      {signedIn ? (
        <div className="auth-actions">
          <button type="button" onClick={() => void onSignOut()} disabled={busy}>
            Sign out
          </button>
        </div>
      ) : (
        <>
          <div className="auth-actions">
            {configured && (
              <button type="button" className="primary" onClick={() => void onGuest()} disabled={busy}>
                Continue as guest
              </button>
            )}
            {configured && (
              <button type="button" onClick={() => setOpen((value) => !value)}>
                {open ? 'Close' : 'Email sign-in'}
              </button>
            )}
          </div>
          {open && configured && (
            <form onSubmit={(event) => void submit(event)}>
              <label>
                Email
                <input
                  type="email"
                  autoComplete="username"
                  value={address}
                  onChange={(event) => setAddress(event.target.value)}
                  required
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  minLength={6}
                  required
                />
              </label>
              <div className="auth-actions">
                <button type="submit" className="primary" disabled={busy}>
                  {mode === 'signup' ? 'Create account' : 'Sign in'}
                </button>
                <button
                  type="button"
                  className="link"
                  onClick={() => setMode((value) => (value === 'signin' ? 'signup' : 'signin'))}
                >
                  {mode === 'signin' ? 'Need an account?' : 'Have an account?'}
                </button>
              </div>
            </form>
          )}
        </>
      )}
    </aside>
  )
}
