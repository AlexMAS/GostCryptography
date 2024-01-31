using System;
using System.Reflection;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Reflection
{
    static class SignedCmsHelper
    {
        private const string MessageHandleFieldName = "m_safeCryptMsgHandle";

        private static readonly Lazy<FieldInfo> MessageHandleField = new Lazy<FieldInfo>(() =>
        {
            var field = typeof(SignedCms).GetField(MessageHandleFieldName, BindingFlags.Instance | BindingFlags.NonPublic);
            return field ?? throw ExceptionUtility.CryptographicException(Resources.SignedCmsCannotFindPrivateMember, MessageHandleFieldName);
        });

        [SecuritySafeCritical]
        private static SafeHandle GetMessageHandle(SignedCms signedCms)
        {
            return MessageHandleField.Value.GetValue(signedCms) as SafeHandle;
        }

        [SecuritySafeCritical]
        public static void RemoveCertificate(this SignedCms signedCms, X509Certificate2 certificate)
        {
            var messageHandle = GetMessageHandle(signedCms);

            if (messageHandle == null)
            {
                return;
            }

            var certIndex = 0;
            var certData = certificate.RawData;

            foreach (var currentCertificate in signedCms.Certificates)
            {
                var currentCertData = currentCertificate.RawData;

                if (SequenceEquals(certData, currentCertData))
                {
                    CryptoApiHelper.RemoveCertificate(messageHandle, certIndex);
                    return;
                }

                ++certIndex;
            }
        }

        [SecuritySafeCritical]
        public static void RemoveCertificates(this SignedCms signedCms)
        {
            var messageHandle = GetMessageHandle(signedCms);

            if (messageHandle == null)
            {
                return;
            }

            var certCount = signedCms.Certificates.Count;

            if (certCount == 0)
            {
                return;
            }

            for (var i = 0; i < certCount; ++i)
            {
                CryptoApiHelper.RemoveCertificate(messageHandle, 0);
            }
        }

        // TODO: Replace with Span.SequenceEquals()
        [SecuritySafeCritical]
        private static unsafe bool SequenceEquals(byte[] a1, byte[] a2)
        {
            unchecked
            {
                if (a1 == a2)
                {
                    return true;
                }

                if (a1 == null || a2 == null || a1.Length != a2.Length)
                {
                    return false;
                }

                fixed (byte* p1 = a1, p2 = a2)
                {
                    byte* x1 = p1, x2 = p2;
                    int l = a1.Length;

                    for (int i = 0; i < l / 8; i++, x1 += 8, x2 += 8)
                    {
                        if (*(long*)x1 != *(long*)x2)
                        {
                            return false;
                        }
                    }

                    if ((l & 4) != 0)
                    {
                        if (*(int*)x1 != *(int*)x2)
                        {
                            return false;
                        }

                        x1 += 4; x2 += 4;
                    }

                    if ((l & 2) != 0)
                    {
                        if (*(short*)x1 != *(short*)x2)
                        {
                            return false;
                        }

                        x1 += 2; x2 += 2;
                    }

                    return ((l & 1) == 0 || *x1 == *x2);
                }
            }
        }
    }
}
