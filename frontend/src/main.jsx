import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import { I18nProvider } from './i18n.jsx';
import '@xterm/xterm/css/xterm.css';
import './styles.css';

const root = document.getElementById('root');
createRoot(root).render(
  <I18nProvider>
    <App />
  </I18nProvider>
);
