const loginForm = document.querySelector('#loginForm');
const setupForm = document.querySelector('#setupForm');
const resetForm = document.querySelector('#resetForm');
const message = document.querySelector('#loginMessage');
const title = document.querySelector('#formTitle');
const intro = document.querySelector('#introMessage');
const loginButton = document.querySelector('#loginButton');
const setupButton = document.querySelector('#setupButton');
const resetSubmitButton = document.querySelector('#resetSubmitButton');
const savedUsernameKey = 'purehai_saved_username';

try {
  const savedUsername = localStorage.getItem(savedUsernameKey);
  if (savedUsername) {
    document.querySelector('#loginUsername').value = savedUsername;
  }
} catch (error) {
  console.warn('Could not restore the saved username:', error);
}

function rememberUsername(username, rememberMe) {
  try {
    if (rememberMe) localStorage.setItem(savedUsernameKey, username);
    else localStorage.removeItem(savedUsernameKey);
  } catch (error) {
    console.warn('Could not save the username on this device:', error);
  }
}

async function postAuth(path, payload) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed. Please try again.');
  return result;
}

function showMode(mode) {
  loginForm.hidden = mode !== 'login';
  setupForm.hidden = mode !== 'setup';
  resetForm.hidden = mode !== 'reset';
  message.textContent = '';
  if (mode === 'login') {
    title.textContent = 'PUREHAI mein login karein';
    intro.textContent = 'Apna saved ID aur password daal kar login karein.';
  } else if (mode === 'setup') {
    title.textContent = 'Pehli baar ID/password banayein';
    intro.textContent = 'Apna ID aur password ek baar save karein. Agli baar isi se login hoga.';
  } else {
    title.textContent = 'Login ID/password reset';
    intro.textContent = 'Admin reset key daal kar naya ID aur password set karein.';
  }
}

loginForm.addEventListener('submit', async event => {
  event.preventDefault();
  loginButton.disabled = true;
  message.textContent = '';
  try {
    const username = document.querySelector('#loginUsername').value;
    const rememberMe = document.querySelector('#rememberMe').checked;
    await postAuth('/api/auth/login', {
      username,
      password: document.querySelector('#loginPassword').value,
      rememberMe
    });
    rememberUsername(username, rememberMe);
    window.location.replace('/');
  } catch (error) {
    message.textContent = error.message;
  } finally {
    loginButton.disabled = false;
  }
});

setupForm.addEventListener('submit', async event => {
  event.preventDefault();
  const username = document.querySelector('#setupUsername').value;
  const password = document.querySelector('#setupPassword').value;
  if (password !== document.querySelector('#confirmPassword').value) {
    message.textContent = 'Dono password ek jaise nahi hain.';
    return;
  }
  setupButton.disabled = true;
  message.textContent = '';
  try {
    const rememberMe = document.querySelector('#rememberSetup').checked;
    await postAuth('/api/auth/setup', { username, password, rememberMe });
    rememberUsername(username, rememberMe);
    window.location.replace('/');
  } catch (error) {
    message.textContent = error.message;
  } finally {
    setupButton.disabled = false;
  }
});

resetForm.addEventListener('submit', async event => {
  event.preventDefault();
  const password = document.querySelector('#resetPassword').value;
  if (password !== document.querySelector('#resetConfirmPassword').value) {
    message.textContent = 'Dono password ek jaise nahi hain.';
    return;
  }
  resetSubmitButton.disabled = true;
  message.textContent = '';
  try {
    await postAuth('/api/auth/reset', {
      resetKey: document.querySelector('#resetKey').value,
      username: document.querySelector('#resetUsername').value,
      password
    });
    window.location.replace('/');
  } catch (error) {
    message.textContent = error.message;
  } finally {
    resetSubmitButton.disabled = false;
  }
});

document.querySelector('#forgotButton').addEventListener('click', () => showMode('reset'));
document.querySelector('#backToLoginButton').addEventListener('click', () => showMode('login'));

fetch('/api/auth/session')
  .then(response => response.json())
  .then(result => {
    if (result.authenticated) {
      window.location.replace('/');
      return;
    }
    showMode(result.credentialsConfigured ? 'login' : 'setup');
  })
  .catch(() => {
    intro.textContent = 'Login service se sampark nahi ho pa raha. Server check karein.';
    message.textContent = 'Server connection check karein aur page dobara kholein.';
  });
