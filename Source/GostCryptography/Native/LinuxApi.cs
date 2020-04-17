using GostCryptography.Base;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace GostCryptography.Native
{
    class LinuxApi : INativeApi
    {
        private readonly ProviderType _providerType;

        public LinuxApi(ProviderType type)
        {
            _providerType = type;
        }
        public bool CertCloseStore(SafeStore hCertStore, uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CertCloseStore(hCertStore, dwFlags);
            else
                return LinuxVipNetNativeApi.CertCloseStore(hCertStore, dwFlags);
        }

        public IntPtr CertEnumCertificatesInStore([In] SafeStore hCertStore, [In] IntPtr pPrevCertContext)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
            else
                return LinuxVipNetNativeApi.CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
        }

        public bool CertGetCertificateContextProperty([In] IntPtr pCertContext, [In] uint dwPropId, [Out] IntPtr pvData, [In, Out] ref uint pcbData)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, ref pcbData);
            else
                return LinuxVipNetNativeApi.CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, ref pcbData);
        }

        public uint CertGetNameString([In] IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara, byte[] pszNameString, uint cchNameString)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString);
            else
                return LinuxVipNetNativeApi.CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString);
        }

        public SafeStore CertOpenSystemStore(SafeStore hCertStore, string pszStoreName)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CertOpenSystemStore(hCertStore, pszStoreName);
            else
                return LinuxVipNetNativeApi.CertOpenSystemStore(hCertStore, pszStoreName);
        }

        public bool CryptAcquireContext([In, Out] ref SafeProvHandleImpl hProv, [In] string pszContainer,
            [In] string pszProvider, [In] uint dwProvType, [In] uint dwFlags)
        {
            bool result;
            try
            {
                //This string depends on encoding of system
                var containerNamePtr = MarshalString(pszContainer);
                var providerNamePtr = MarshalString(pszProvider);
                result = _providerType.IsCryptoPro()
                    ? LinuxCryptoProNativeApi.CryptAcquireContext(ref hProv, containerNamePtr, providerNamePtr, dwProvType, dwFlags)
                    : LinuxVipNetNativeApi.CryptAcquireContext(ref hProv, containerNamePtr, providerNamePtr, dwProvType,
                        dwFlags);
                Marshal.FreeHGlobal(containerNamePtr);
                Marshal.FreeHGlobal(providerNamePtr);
            }
            catch
            {
                result = false;
            }

            return result;
        }

        public bool CryptContextAddRef([In] IntPtr hProv, [In] byte[] pdwReserved, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptContextAddRef(hProv, pdwReserved, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptContextAddRef(hProv, pdwReserved, dwFlags);
        }

        public bool CryptCreateHash([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags, [In, Out] ref SafeHashHandleImpl phHash)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptCreateHash(hProv, Algid, hKey, dwFlags, ref phHash);
            else
                return LinuxVipNetNativeApi.CryptCreateHash(hProv, Algid, hKey, dwFlags, ref phHash);
        }

        public bool CryptDecrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In, MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In, Out] byte[] pbData, ref uint pdwDataLen)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen);
            else
                return LinuxVipNetNativeApi.CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen);
        }

        public bool CryptDeriveKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeHashHandleImpl hBaseData, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, ref phKey);
            else
                return LinuxVipNetNativeApi.CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, ref phKey);
        }

        public bool CryptDestroyHash(IntPtr pHashCtx)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptDestroyHash(pHashCtx);
            else
                return LinuxVipNetNativeApi.CryptDestroyHash(pHashCtx);
        }

        public bool CryptDestroyKey(IntPtr pKeyCtx)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptDestroyKey(pKeyCtx);
            else
                return LinuxVipNetNativeApi.CryptDestroyKey(pKeyCtx);
        }

        public bool CryptDuplicateKey([In] IntPtr hKey, [In] byte[] pdwReserved, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptDuplicateKey(hKey, pdwReserved, dwFlags, ref phKey);
            else
                return LinuxVipNetNativeApi.CryptDuplicateKey(hKey, pdwReserved, dwFlags, ref phKey);
        }

        public bool CryptEncrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In, MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In, Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwBufLen)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen, dwBufLen);
            else
                return LinuxVipNetNativeApi.CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen, dwBufLen);
        }

        public bool CryptExportKey([In] SafeKeyHandleImpl hKey, [In] SafeKeyHandleImpl hExpKey, [In] uint dwBlobType, [In] uint dwFlags, [Out] byte[] pbData, ref uint pdwDataLen)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, ref pdwDataLen);
            else
                return LinuxVipNetNativeApi.CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, ref pdwDataLen);
        }

        public bool CryptGenKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptGenKey(hProv, Algid, dwFlags, ref phKey);
            else
                return LinuxVipNetNativeApi.CryptGenKey(hProv, Algid, dwFlags, ref phKey);
        }

        public bool CryptGetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In, Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
        }

        public bool CryptGetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In, Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptGetKeyParam(hKey, dwParam, pbData, ref pdwDataLen, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptGetKeyParam(hKey, dwParam, pbData, ref pdwDataLen, dwFlags);
        }

        public bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In, Out] byte[] pbData, ref uint dwDataLen, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData, ref uint dwDataLen, uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.U8)] long pbData, ref uint dwDataLen, uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public bool CryptGetUserKey([In] SafeProvHandleImpl hProv, [In] uint dwKeySpec, [In, Out] ref SafeKeyHandleImpl phUserKey)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptGetUserKey(hProv, dwKeySpec, ref phUserKey);
            else
                return LinuxVipNetNativeApi.CryptGetUserKey(hProv, dwKeySpec, ref phUserKey);
        }

        public bool CryptHashData([In] SafeHashHandleImpl hHash, [In, Out] byte[] pbData, [In] uint dwDataLen, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
        }

        public unsafe bool CryptHashData([In] SafeHashHandleImpl hHash, byte* pbData, [In] uint dwDataLen, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
        }

        public bool CryptHashSessionKey([In] SafeHashHandleImpl hHash, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptHashSessionKey(hHash, hKey, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptHashSessionKey(hHash, hKey, dwFlags);
        }

        public bool CryptImportKey([In] SafeProvHandleImpl hCryptProv, [In] byte[] pbData, [In] uint dwDataLen, [In] SafeKeyHandleImpl hPubKey, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptImportKey(hCryptProv, pbData, dwDataLen, hPubKey, dwFlags, ref phKey);
            else
                return LinuxVipNetNativeApi.CryptImportKey(hCryptProv, pbData, dwDataLen, hPubKey, dwFlags, ref phKey);
        }

        public bool CryptImportPublicKeyInfo([In] SafeProvHandleImpl hCryptProv, [In] uint dwCertEncodingType, [In] /*CERT_PUBLIC_KEY_INFO*/ IntPtr pPublicKeyInfo, [Out][In] ref SafeKeyHandleImpl phKey)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pPublicKeyInfo, ref phKey);
            else
                return LinuxVipNetNativeApi.CryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pPublicKeyInfo, ref phKey);
        }

        public bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptReleaseContext(hCryptProv, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptReleaseContext(hCryptProv, dwFlags);
        }

        public bool CryptSetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In, Out] byte[] pbData, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
        }

        public bool CryptSetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptSetKeyParam(hKey, dwParam, pbData, dwParam);
            else
                return LinuxVipNetNativeApi.CryptSetKeyParam(hKey, dwParam, pbData, dwParam);
        }

        public bool CryptSetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In] IntPtr pbData, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptSetProvParam(hProv, dwParam, pbData, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptSetProvParam(hProv, dwParam, pbData, dwFlags);
        }

        public bool CryptSetProvParam2(IntPtr hCryptProv, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CryptSetProvParam2(hCryptProv, dwParam, pbData, dwFlags);
            else
                return LinuxVipNetNativeApi.CryptSetProvParam2(hCryptProv, dwParam, pbData, dwFlags);
        }

        public bool CryptSignHash([In] SafeHashHandleImpl hHash, [In] uint dwKeySpec, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sDescription, [In] uint dwFlags, [In, Out] byte[] pbSignature, ref uint pdwSigLen)
        {
            var sDecriptionPtr = MarshalStringBuilder(sDescription);
            var result = _providerType.IsCryptoPro() ?
                LinuxCryptoProNativeApi.CryptSignHash(hHash, dwKeySpec, sDecriptionPtr, dwFlags, pbSignature, ref pdwSigLen) :
                LinuxVipNetNativeApi.CryptSignHash(hHash, dwKeySpec, sDecriptionPtr, dwFlags, pbSignature, ref pdwSigLen);
            Marshal.FreeHGlobal(sDecriptionPtr);
            return result;
        }

        public bool CryptVerifySignature([In] SafeHashHandleImpl hHash, [In, Out] byte[] pbSignature, uint pdwSigLen, [In] SafeKeyHandleImpl hPubKey, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sDescription, [In] uint dwFlags)
        {
            var sDecriptionPtr = MarshalStringBuilder(sDescription);
            var result = _providerType.IsCryptoPro() ?
                LinuxCryptoProNativeApi.CryptVerifySignature(hHash, pbSignature, pdwSigLen, hPubKey, sDecriptionPtr, dwFlags) :
                LinuxVipNetNativeApi.CryptVerifySignature(hHash, pbSignature, pdwSigLen, hPubKey, sDecriptionPtr, dwFlags);
            Marshal.FreeHGlobal(sDecriptionPtr);
            return result;
        }

        public IntPtr CertCreateCertificateContext(
            uint dwCertEncodingType,
            byte[] pCertEncoded,
            int cbCertEncoded)
        {
            if (_providerType.IsCryptoPro())
                return LinuxCryptoProNativeApi.CertCreateCertificateContext(dwCertEncodingType, pCertEncoded, cbCertEncoded);
            else
                return LinuxVipNetNativeApi.CertCreateCertificateContext(dwCertEncodingType, pCertEncoded, cbCertEncoded);
        }

        private IntPtr MarshalString(string str)
        {
            if (str == null) return IntPtr.Zero;
            str += '\0'; //add end of string
            var buffer = Encoding.UTF32.GetBytes(str);
            var result = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, result, buffer.Length);
            return result;
        }

        private IntPtr MarshalStringBuilder(StringBuilder builder)
        {
            if (builder == null) return IntPtr.Zero; //rigth now string builder in arguments always null
            return MarshalString(builder.ToString());
        }
    }
}
