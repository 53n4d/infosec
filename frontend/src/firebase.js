import { initializeApp } from 'firebase/app'
import { getFirestore } from 'firebase/firestore'

const firebaseConfig = {
  apiKey: "AIzaSyAFFzX9nKuDYPUk2n_-a3-cuLSnvWc49fY",
  authDomain: "xseverity-recon.firebaseapp.com",
  projectId: "xseverity-recon",
  storageBucket: "xseverity-recon.firebasestorage.app",
  messagingSenderId: "790666961183",
  appId: "1:790666961183:web:df57cc36afb417e690d02a",
  measurementId: "G-TKTZY1SMRZ"
}

const app = initializeApp(firebaseConfig)
export const db = getFirestore(app)