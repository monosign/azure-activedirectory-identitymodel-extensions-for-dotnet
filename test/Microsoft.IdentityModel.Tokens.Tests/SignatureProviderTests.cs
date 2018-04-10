//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

using EE = Microsoft.IdentityModel.Tests.ExpectedException;
using KM = Microsoft.IdentityModel.Tests.KeyingMaterial;
using SA = Microsoft.IdentityModel.Tokens.SecurityAlgorithms;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// This class tests:
    /// CryptoProviderFactory
    /// SignatureProvider
    /// SymmetricSignatureProvider
    /// AsymmetricSignatureProvider
    /// </summary>
    public class SignatureProviderTests
    {
        [Theory, MemberData(nameof(SignatureProviderConstructorParamsTheoryData))]
        public void CryptoProviderFactoryConstructorParams(CryptoProviderFactoryTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CryptoProviderFactoryConstructorParams", theoryData);

            try
            {
                if (theoryData.WillCreateSignatures)
                    theoryData.CryptoProviderFactory.CreateForSigning(theoryData.SigningKey, theoryData.SigningAlgorithm);
                else
                    theoryData.CryptoProviderFactory.CreateForVerifying(theoryData.SigningKey, theoryData.SigningAlgorithm);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(SignatureProviderConstructorParamsTheoryData))]
        public void AsymmetricSignatureProviderConstructorParams(SignatureProviderTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.AsymmetricSignatureProviderConstructorParams", theoryData);

            try
            {
                new AsymmetricSignatureProvider(theoryData.SigningKey, theoryData.SigningAlgorithm, theoryData.WillCreateSignatures);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(SignatureProviderConstructorParamsTheoryData))]
        public void SymmetricSignatureProviderConstructorParams(SignatureProviderTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SymmetricSignatureProviderConstructorParams", theoryData);

            try
            {
                new SymmetricSignatureProvider(theoryData.SigningKey, theoryData.SigningAlgorithm);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureProviderTheoryData> SignatureProviderConstructorParamsTheoryData
        {
            get => new TheoryData<SignatureProviderTheoryData>
            {
                new SignatureProviderTheoryData
                {
                    SigningAlgorithm = string.Empty,
                    ExpectedException = EE.ArgumentNullException(),
                    First = true,
                    SigningKey = KM.X509SecurityKey_1024,
                    TestId = "Algorithm-string.Empty",
                    WillCreateSignatures = true
                },
                new SignatureProviderTheoryData
                {
                    SigningAlgorithm = null,
                    ExpectedException = EE.ArgumentNullException(),
                    SigningKey = KM.X509SecurityKey_1024,
                    TestId = "Algorithm-null"
                },
                new SignatureProviderTheoryData
                {
                    SigningAlgorithm = SA.RsaSha256,
                    ExpectedException = EE.ArgumentNullException(),
                    SigningKey = null,
                    TestId = "Key-null",
                },
            };
        }

        [Theory, MemberData(nameof(SignAndVerifyTheoryData))]
        public void SignAndVerify(SignatureProviderTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateSignatureProvider", theoryData);
            try
            {
                var signatureProviderVerify = CryptoProviderFactory.Default.CreateForVerifying(theoryData.VerifyingKey, theoryData.VerifyingAlgorithm);
                var signatureProviderSign = CryptoProviderFactory.Default.CreateForSigning(theoryData.SigningKey, theoryData.SigningAlgorithm);
                var bytes = Encoding.UTF8.GetBytes("GenerateASignature");
                var signature = signatureProviderSign.Sign(bytes);
                if (!signatureProviderVerify.Verify(bytes, signature))
                    throw new SecurityTokenInvalidSignatureException("SignatureFailed");

                CryptoProviderFactory.Default.ReleaseSignatureProvider(signatureProviderSign);
                CryptoProviderFactory.Default.ReleaseSignatureProvider(signatureProviderVerify);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureProviderTheoryData> SignAndVerifyTheoryData
        {
            get => new TheoryData<SignatureProviderTheoryData>
            {
                new SignatureProviderTheoryData("ECDsa1", SA.EcdsaSha256, SA.EcdsaSha256, KM.Ecdsa256Key, KM.Ecdsa256Key_Public),
                new SignatureProviderTheoryData("ECDsa2", SA.EcdsaSha384, SA.EcdsaSha384, KM.Ecdsa256Key, KM.Ecdsa256Key_Public, EE.NotSupportedException("IDX10641:")),
                new SignatureProviderTheoryData("ECDsa3", SA.EcdsaSha512, SA.EcdsaSha512, KM.Ecdsa256Key, KM.Ecdsa256Key_Public,EE.NotSupportedException("IDX10641:")),
                new SignatureProviderTheoryData("ECDsa4", SA.EcdsaSha256Signature, SA.EcdsaSha256Signature, KM.Ecdsa256Key, KM.Ecdsa256Key_Public),
                new SignatureProviderTheoryData("ECDsa5", SA.EcdsaSha384Signature, SA.EcdsaSha384Signature, KM.Ecdsa256Key, KM.Ecdsa256Key_Public, EE.NotSupportedException("IDX10641:")),
                new SignatureProviderTheoryData("ECDsa6", SA.EcdsaSha512Signature, SA.EcdsaSha512Signature, KM.Ecdsa256Key, KM.Ecdsa256Key_Public, EE.NotSupportedException("IDX10641:")),
                new SignatureProviderTheoryData("ECDsa7", SA.Aes128Encryption, SA.EcdsaSha256Signature, KM.Ecdsa256Key, KM.Ecdsa256Key_Public, EE.NotSupportedException("IDX10634:")),
                new SignatureProviderTheoryData("ECDsa8", SA.EcdsaSha384, SA.EcdsaSha384, KM.Ecdsa384Key, KM.Ecdsa384Key_Public),
                new SignatureProviderTheoryData("ECDsa9", SA.EcdsaSha512, SA.EcdsaSha512, KM.Ecdsa521Key, KM.Ecdsa521Key_Public),

                new SignatureProviderTheoryData("JsonWebKeyEcdsa1", SA.EcdsaSha256, SA.EcdsaSha256, KM.JsonWebKeyEcdsa256, KM.JsonWebKeyEcdsa256_Public),
                new SignatureProviderTheoryData("JsonWebKeyEcdsa2", SA.EcdsaSha256Signature, SA.EcdsaSha256Signature, KM.JsonWebKeyEcdsa256, KM.JsonWebKeyEcdsa256_Public),
                new SignatureProviderTheoryData("JsonWebKeyEcdsa3", SA.Aes256KeyWrap, SA.EcdsaSha256Signature, KM.JsonWebKeyEcdsa256, KM.JsonWebKeyEcdsa256_Public, EE.NotSupportedException("IDX10634:")),
                new SignatureProviderTheoryData("JsonWebKeyRsa1", SA.RsaSha256, SA.RsaSha256, KM.JsonWebKeyRsa256, KM.JsonWebKeyRsa256Public),
                new SignatureProviderTheoryData("JsonWebKeyRsa2", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.JsonWebKeyRsa256, KM.JsonWebKeyRsa256Public),
                new SignatureProviderTheoryData("JsonWebKeyRsa3", SA.Aes192KeyWrap, SA.RsaSha256Signature, KM.JsonWebKeyRsa256, KM.JsonWebKeyRsa256Public, EE.NotSupportedException("IDX10634:")),
                new SignatureProviderTheoryData("JsonWebKeySymmetric1", SA.HmacSha256, SA.HmacSha256, KM.JsonWebKeySymmetric256, KM.JsonWebKeySymmetric256),
                new SignatureProviderTheoryData("JsonWebKeySymmetric2", SA.HmacSha256Signature, SA.HmacSha256Signature, KM.JsonWebKeySymmetric256, KM.JsonWebKeySymmetric256),
                new SignatureProviderTheoryData("JsonWebKeySymmetric3", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.JsonWebKeySymmetric256, KM.JsonWebKeyRsa256Public, EE.NotSupportedException("IDX10634:")),
                new SignatureProviderTheoryData("JsonWebKeySymmetric4", SA.EcdsaSha512Signature, SA.EcdsaSha512Signature, KM.JsonWebKeySymmetric256, KM.JsonWebKeyRsa256Public, EE.NotSupportedException("IDX10634:")),

                new SignatureProviderTheoryData("RsaSecurityKey1", SA.RsaSha256, SA.RsaSha256, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public),
                new SignatureProviderTheoryData("RsaSecurityKey2", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public),
                new SignatureProviderTheoryData("RsaSecurityKey3", SA.RsaSha384, SA.RsaSha384, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public),
                new SignatureProviderTheoryData("RsaSecurityKey4", SA.RsaSha384Signature, SA.RsaSha384Signature, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public),
                new SignatureProviderTheoryData("RsaSecurityKey5", SA.RsaSha512, SA.RsaSha512, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public),
                new SignatureProviderTheoryData("RsaSecurityKey6", SA.RsaSha512Signature, SA.RsaSha512Signature, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public),
                new SignatureProviderTheoryData("RsaSecurityKey7", SA.Aes128Encryption, SA.RsaSha512, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public, EE.NotSupportedException("IDX10634:")),
                new SignatureProviderTheoryData("RsaSecurityKey8", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.RsaSecurityKey_4096, KM.RsaSecurityKey_4096_Public),
                new SignatureProviderTheoryData("RsaSecurityKey9", SA.RsaSha384Signature, SA.RsaSha384Signature, KM.RsaSecurityKey_4096, KM.RsaSecurityKey_4096_Public),
                new SignatureProviderTheoryData("RsaSecurityKey10", SA.RsaSha512Signature, SA.RsaSha512Signature, KM.RsaSecurityKey_4096, KM.RsaSecurityKey_4096_Public),

                new SignatureProviderTheoryData("X509SecurityKey1", SA.RsaSha256, SA.RsaSha256, KM.X509SecurityKeySelfSigned2048_SHA256, KM.X509SecurityKeySelfSigned2048_SHA256_Public),
                new SignatureProviderTheoryData("X509SecurityKey2", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.X509SecurityKeySelfSigned2048_SHA256, KM.X509SecurityKeySelfSigned2048_SHA256_Public),
                new SignatureProviderTheoryData("X509SecurityKey3", SA.RsaSha384, SA.RsaSha384, KM.X509SecurityKeySelfSigned2048_SHA256, KM.X509SecurityKeySelfSigned2048_SHA256_Public),
                new SignatureProviderTheoryData("X509SecurityKey4", SA.RsaSha384Signature, SA.RsaSha384Signature, KM.X509SecurityKeySelfSigned2048_SHA256, KM.X509SecurityKeySelfSigned2048_SHA256_Public),
                new SignatureProviderTheoryData("X509SecurityKey5", SA.RsaSha512, SA.RsaSha512, KM.X509SecurityKeySelfSigned2048_SHA256, KM.X509SecurityKeySelfSigned2048_SHA256_Public),
                new SignatureProviderTheoryData("X509SecurityKey6", SA.RsaSha512Signature, SA.RsaSha512Signature, KM.X509SecurityKeySelfSigned2048_SHA256, KM.X509SecurityKeySelfSigned2048_SHA256_Public),
                new SignatureProviderTheoryData("X509SecurityKey7", SA.Aes128Encryption, SA.RsaSha512Signature, KM.X509SecurityKeySelfSigned2048_SHA256, KM.X509SecurityKeySelfSigned2048_SHA256_Public, EE.NotSupportedException("IDX10634:")),
                new SignatureProviderTheoryData("X509SecurityKey8", SA.RsaSha256Signature, SA.RsaSha512Signature, KM.DefaultX509Key_2048, KM.DefaultX509Key_2048_Public, EE.SecurityTokenInvalidSignatureException()),

                new SignatureProviderTheoryData("SymmetricSecurityKey1", SA.HmacSha256, SA.HmacSha256, KM.SymmetricSecurityKey2_256, KM.SymmetricSecurityKey2_256),
                new SignatureProviderTheoryData("SymmetricSecurityKey2", SA.HmacSha256Signature, SA.HmacSha256Signature, KM.SymmetricSecurityKey2_256, KM.SymmetricSecurityKey2_256),
                new SignatureProviderTheoryData("SymmetricSecurityKey3", SA.RsaSha256Signature, SA.RsaSha512Signature, KM.SymmetricSecurityKey2_256, KM.SymmetricSecurityKey2_256, EE.NotSupportedException("IDX10634:")),
#if NET452
                new SignatureProviderTheoryData("RsaSecurityKeyWithCspProvider1", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.RsaSecurityKeyWithCspProvider_2048, KM.RsaSecurityKeyWithCspProvider_2048_Public),
                new SignatureProviderTheoryData("RsaSecurityKeyWithCspProvider2", SA.RsaSha384Signature, SA.RsaSha384Signature, KM.RsaSecurityKeyWithCspProvider_2048, KM.RsaSecurityKey_2048_Public),
#endif
                new SignatureProviderTheoryData("NotAsymmetricOrSymmetricSecurityKey1", SA.HmacSha256Signature, SA.HmacSha256Signature, NotAsymmetricOrSymmetricSecurityKey.New, KM.SymmetricSecurityKey2_256, EE.NotSupportedException("IDX10634:")),
                new SignatureProviderTheoryData("NotAsymmetricOrSymmetricSecurityKey2", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.SymmetricSecurityKey2_256, NotAsymmetricOrSymmetricSecurityKey.New, EE.NotSupportedException("IDX10634:")),

                // Private keys missing
                new SignatureProviderTheoryData("PrivateKey1", SA.EcdsaSha256, SA.EcdsaSha256, KM.JsonWebKeyEcdsa256_Public, KM.JsonWebKeyEcdsa256_Public, EE.InvalidOperationException("IDX10638:")),
                new SignatureProviderTheoryData("PrivateKey2", SA.RsaSha256, SA.RsaSha256, KM.JsonWebKeyRsa256Public, KM.JsonWebKeyRsa256Public, EE.InvalidOperationException("IDX10638:")),
                new SignatureProviderTheoryData("PrivateKey3", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.RsaSecurityKey_2048_Public,KM.RsaSecurityKey_2048_Public, EE.InvalidOperationException("IDX10638:")),
                new SignatureProviderTheoryData("PrivateKey4", SA.RsaSha256, SA.RsaSha256, KM.X509SecurityKeySelfSigned2048_SHA256_Public, KM.X509SecurityKeySelfSigned2048_SHA256_Public, EE.InvalidOperationException("IDX10638:")),
                new SignatureProviderTheoryData("PrivateKey5", SA.EcdsaSha512, SA.EcdsaSha512, KM.Ecdsa521Key_Public, KM.Ecdsa521Key_Public, EE.InvalidOperationException("IDX10638:")),

                // Key size checks
                new SignatureProviderTheoryData("KeySize1", SA.RsaSha256, SA.RsaSha256, KM.RsaSecurityKey_1024, KM.RsaSecurityKey_1024, EE.ArgumentOutOfRangeException("IDX10630:")),
                new SignatureProviderTheoryData("KeySize2", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.X509SecurityKey_1024,KM.X509SecurityKey_1024, EE.ArgumentOutOfRangeException("IDX10630:")),
                new SignatureProviderTheoryData("KeySize3", SA.HmacSha256Signature, SA.HmacSha256Signature, KM.DefaultSymmetricSecurityKey_56, KM.DefaultSymmetricSecurityKey_56, EE.ArgumentOutOfRangeException("IDX10603:")),

                // signing and verifying with different keys
                new SignatureProviderTheoryData("DifferentKey1", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_4096_Public, EE.SecurityTokenInvalidSignatureException()),
                new SignatureProviderTheoryData("DifferentKey2", SA.RsaSha256Signature, SA.RsaSha256Signature, KM.RsaSecurityKey_4096, KM.RsaSecurityKey_2048_Public, EE.SecurityTokenInvalidSignatureException()),

                // KeyAlgorithmMismatch
                new SignatureProviderTheoryData("KeyAlgorithmMismatch1", SA.RsaSha512Signature, SA.RsaSha256Signature, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public, EE.SecurityTokenInvalidSignatureException()),
                new SignatureProviderTheoryData("KeyAlgorithmMismatch2", SA.EcdsaSha512, SA.EcdsaSha256, KM.Ecdsa256Key, KM.Ecdsa256Key_Public, EE.NotSupportedException()),
                new SignatureProviderTheoryData("KeyAlgorithmMismatch3", SA.EcdsaSha256, SA.EcdsaSha512, KM.Ecdsa256Key, KM.Ecdsa256Key_Public, EE.NotSupportedException()),
                new SignatureProviderTheoryData("KeyAlgorithmMismatch4", SA.EcdsaSha512, SA.EcdsaSha256, KM.JsonWebKeyEcdsa256, KM.JsonWebKeyEcdsa256_Public, EE.NotSupportedException()),
                new SignatureProviderTheoryData("KeyAlgorithmMismatch5", SA.EcdsaSha256, SA.EcdsaSha512, KM.JsonWebKeyEcdsa256, KM.JsonWebKeyEcdsa256_Public, EE.NotSupportedException()),

                // NotSupported
                new SignatureProviderTheoryData("NotSupported1", "SA.RsaSha256", SA.RsaSha256, KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public, EE.NotSupportedException()),
                new SignatureProviderTheoryData("NotSupported2", SA.RsaSha256, "SA.RsaSha256", KM.RsaSecurityKey_2048, KM.RsaSecurityKey_2048_Public, EE.NotSupportedException()),
                new SignatureProviderTheoryData("NotSupported3", "SA.RsaSha256Signature", SA.RsaSha256Signature, KM.X509SecurityKey_1024, KM.X509SecurityKey_1024, EE.NotSupportedException()),
                new SignatureProviderTheoryData("NotSupported4", SA.RsaSha256Signature, "SA.RsaSha256Signature", KM.X509SecurityKey_1024, KM.X509SecurityKey_1024, EE.NotSupportedException()),

                // BadKeys
                new SignatureProviderTheoryData("BadKeys1", SA.EcdsaSha256, SA.EcdsaSha256, KM.JsonWebKeyEcdsa256, KM.JsonWebKeyPublicWrongX, EE.ArgumentOutOfRangeException()),
                new SignatureProviderTheoryData("BadKeys2", SA.EcdsaSha256, SA.EcdsaSha256, KM.JsonWebKeyEcdsa256, KM.JsonWebKeyPublicWrongY, EE.ArgumentOutOfRangeException()),
            };
        }

        #region Common Signature Provider Tests
        [Fact]
        public void SignatureProvider_Dispose()
        {
            AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider(KM.DefaultX509Key_2048_Public, SA.RsaSha256Signature);
            asymmetricSignatureProvider.Dispose();

            var expectedException = EE.ObjectDisposedException;
            SignatureProvider_DisposeVariation("Sign", asymmetricSignatureProvider, expectedException);
            SignatureProvider_DisposeVariation("Verify", asymmetricSignatureProvider, expectedException);
            SignatureProvider_DisposeVariation("Dispose", asymmetricSignatureProvider, EE.NoExceptionExpected);

            SymmetricSignatureProvider symmetricProvider = new SymmetricSignatureProvider(KM.DefaultSymmetricSecurityKey_256, KM.DefaultSymmetricSigningCreds_256_Sha2.Algorithm);
            symmetricProvider.Dispose();
            SignatureProvider_DisposeVariation("Sign", symmetricProvider, expectedException);
            SignatureProvider_DisposeVariation("Verify", symmetricProvider, expectedException);
            SignatureProvider_DisposeVariation("Dispose", symmetricProvider, EE.NoExceptionExpected);
        }

        private void SignatureProvider_DisposeVariation(string testCase, SignatureProvider provider, ExpectedException expectedException)
        {
            try
            {
                if (testCase.StartsWith("Sign"))
                    provider.Sign(new byte[256]);
                else if (testCase.StartsWith("Verify"))
                    provider.Verify(new byte[256], new byte[256]);
                else if (testCase.StartsWith("Dispose"))
                    provider.Dispose();
                else
                    Assert.True(false, "Test case does not match any scenario");

                expectedException.ProcessNoException();
            }
            catch(Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        private void AsymmetricSignatureProvidersSignVariation(SecurityKey key, string algorithm, byte[] input, ExpectedException ee, List<string> errors)
        {
            try
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm, true);
                byte[] signature = provider.Sign(input);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }

        private void SymmetricSignatureProvidersSignVariation(SecurityKey key, string algorithm, byte[] input, ExpectedException ee, List<string> errors)
        {
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
                byte[] signature = provider.Sign(input);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }
        #endregion

        #region Asymmetric Signature Provider Tests
        [Fact]
        public void AsymmetricSignatureProvider_SupportedAlgorithms()
        {
            var errors = new List<string>();

            foreach (var algorithm in
                new string[] {
                    SA.RsaSha256,
                    SA.RsaSha384,
                    SA.RsaSha512,
                    SA.RsaSha256Signature,
                    SA.RsaSha384Signature,
                    SA.RsaSha512Signature })
            {
                try
                {
                    var provider = new AsymmetricSignatureProvider(KM.DefaultX509Key_2048, algorithm);
                }
                catch (Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

            }

            foreach (var algorithm in
                new string[] {
                    SA.EcdsaSha256,
                    SA.EcdsaSha384,
                    SA.EcdsaSha512 })
            {
                try
                {
                    SecurityKey key = null;
                    if (algorithm.Equals(SA.EcdsaSha256, StringComparison.Ordinal))
                    {
                        key = KM.Ecdsa256Key;
                    }
                    else if (algorithm.Equals(SA.EcdsaSha384, StringComparison.Ordinal))
                    {
                        key = KM.Ecdsa384Key;
                    }
                    else
                    {
                        key = KM.Ecdsa521Key;
                    }

                    var provider = new AsymmetricSignatureProvider(key, algorithm);
                }
                catch (Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

            }
            TestUtilities.AssertFailIfErrors("AsymmetricSignatureProvider_SupportedAlgorithms", errors);

        }

        private static bool IsRunningOn462OrGreaterOrCore()
        {
#if NET452
            // test for >=4.6.2
            // AesCng was added to System.Core in 4.6.2. It doesn't exist in .NET Core.
            Module systemCoreModule = typeof(System.Security.Cryptography.AesCryptoServiceProvider).GetTypeInfo().Assembly.GetModules()[0];
            if (systemCoreModule != null && systemCoreModule.GetType("System.Security.Cryptography.AesCng") != null)
                return true;
            return false;
#else
            // test for Core
            return true;
#endif
        }

        [Theory, MemberData(nameof(AsymmetricSignatureProviderVerifyTheoryData))]
        public void AsymmetricSignatureProviderVerify(SignatureProviderTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.AsymmetricSignatureProviderVerify", theoryData);
            try
            {
                var provider = new AsymmetricSignatureProvider(theoryData.SigningKey, theoryData.SigningAlgorithm);
                provider.Verify(theoryData.RawBytes, theoryData.Signature);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureProviderTheoryData> AsymmetricSignatureProviderVerifyTheoryData
        {
            get => new TheoryData<SignatureProviderTheoryData>
            {
                new SignatureProviderTheoryData
                {
                    SigningAlgorithm = SA.RsaSha256Signature,
                    ExpectedException = EE.ArgumentNullException(),
                    SigningKey = KM.RsaSecurityKey_2048,
                    RawBytes = null,
                    Signature = new byte[1],
                    TestId = "RawBytes-NULL"
                },
                new SignatureProviderTheoryData
                {
                    SigningAlgorithm = SA.RsaSha256Signature,
                    ExpectedException = EE.ArgumentNullException(),
                    SigningKey = KM.RsaSecurityKey_2048,
                    RawBytes = new byte[1],
                    Signature = null,
                    TestId = "Signature-NULL"
                },
                new SignatureProviderTheoryData
                {
                    SigningAlgorithm = SA.RsaSha256Signature,
                    ExpectedException = EE.ArgumentNullException(),
                    SigningKey = KM.RsaSecurityKey_2048,
                    RawBytes = new byte[0],
                    Signature = new byte[1],
                    TestId = "RawBytes-Size:0"
                },
                new SignatureProviderTheoryData
                {
                    SigningAlgorithm = SA.RsaSha256Signature,
                    ExpectedException = EE.ArgumentNullException(),
                    SigningKey = KM.RsaSecurityKey_2048,
                    RawBytes = new byte[1],
                    Signature = new byte[0],
                    TestId = "Signature-Size:0"
                }
            };
        }

#endregion

#region Symmetric Signature Provider Tests
        [Fact]
        public void SymmetricSignatureProvider_ConstructorTests()
        {
            // no errors
            SymmetricSignatureProvider_ConstructorVariation(KM.DefaultSymmetricSecurityKey_256, SA.HmacSha256Signature, EE.NoExceptionExpected);
            SymmetricSignatureProvider_ConstructorVariation(KM.JsonWebKeySymmetric256, SA.HmacSha256, EE.NoExceptionExpected);

            // null key
            SymmetricSignatureProvider_ConstructorVariation(null, SA.HmacSha256Signature, EE.ArgumentNullException());

            // empty algorithm
            SymmetricSignatureProvider_ConstructorVariation(KM.DefaultSymmetricSecurityKey_256, string.Empty, EE.ArgumentNullException());

            // unsupported algorithm
            SymmetricSignatureProvider_ConstructorVariation(KM.DefaultSymmetricSecurityKey_256, "unknown algorithm", EE.NotSupportedException("IDX10634:"));

            // smaller key < 256 bytes
            SymmetricSignatureProvider_ConstructorVariation(Default.SymmetricSigningKey56, SA.HmacSha256Signature, EE.ArgumentOutOfRangeException("IDX10603"));
            SymmetricSignatureProvider_ConstructorVariation(Default.SymmetricSigningKey64, SA.HmacSha256Signature, EE.ArgumentOutOfRangeException("IDX10603"));

            // GetKeyedHashAlgorithm throws
            SymmetricSecurityKey key = new FaultingSymmetricSecurityKey(Default.SymmetricSigningKey256, new CryptographicException("Inner CryptographicException"), null, null, Default.SymmetricSigningKey256.Key);
            SymmetricSignatureProvider_ConstructorVariation(key, SA.HmacSha256Signature, EE.InvalidOperationException("IDX10634:", typeof(CryptographicException)));
        }

        private void SymmetricSignatureProvider_ConstructorVariation(SecurityKey key, string algorithm, ExpectedException expectedException)
        {
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [Fact]
        public void SymmetricSignatureProvider_SupportedAlgorithms()
        {
            var errors = new List<string>();

            foreach (var algorithm in
                new string[] {
                    SA.HmacSha256Signature,
                    SA.HmacSha384Signature,
                    SA.HmacSha512Signature,
                    SA.HmacSha256,
                    SA.HmacSha384,
                    SA.HmacSha512 })
            {
                try
                {
                    var provider = new SymmetricSignatureProvider(KM.DefaultSymmetricSecurityKey_256, algorithm);
                }
                catch (Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

                TestUtilities.AssertFailIfErrors("AsymmetricSignatureProvider_SupportedAlgorithms", errors);
            }
        }

        [Fact]
        public void SymmetricSignatureProvider_Publics()
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KM.DefaultSymmetricSecurityKey_256, KM.DefaultSymmetricSigningCreds_256_Sha2.Algorithm);

            ExpectedException expectedException = EE.ArgumentOutOfRangeException("IDX10628:");
            try
            {
                provider.MinimumSymmetricKeySizeInBits = SymmetricSignatureProvider.DefaultMinimumSymmetricKeySizeInBits - 10;
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [Theory, MemberData(nameof(SymmetricSignatureProviderVerifyTheoryData))]
        public void SymmetricSignatureProvidersVerify(SignatureProviderTheoryData testParams)
        {
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(testParams.SigningKey, testParams.SigningAlgorithm);
                if (provider.Verify(testParams.RawBytes, testParams.Signature) != testParams.ShouldVerify)
                    Assert.True(false, testParams.TestId + " - SignatureProvider.Verify did not return expected: " + testParams.ShouldVerify + " , algorithm: " + testParams.SigningAlgorithm);

                testParams.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                testParams.ExpectedException.ProcessException(ex);
            }
        }
#endregion

        public static TheoryData <SignatureProviderTheoryData> SymmetricSignatureProviderVerifyTheoryData()
        {
            var theoryData = new TheoryData<SignatureProviderTheoryData>();

            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

#region Parameter Validation

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                ExpectedException = EE.ArgumentNullException(),
                First = true,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = null,
                ShouldVerify = false,
                Signature = new byte[1],
                TestId = "Test1"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                ExpectedException = EE.ArgumentNullException(),
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = new byte[0],
                ShouldVerify = false,
                Signature = new byte[1],
                TestId = "Test2"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                ExpectedException = EE.ArgumentNullException(),
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = new byte[1],
                ShouldVerify = false,
                Signature = null,
                TestId = "Test3"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                ExpectedException = EE.ArgumentNullException(),
                RawBytes = new byte[1],
                SigningKey = Default.SymmetricSigningKey256,
                ShouldVerify = false,
                Signature = new byte[0],
                TestId = "Test4"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = new byte[1],
                ShouldVerify = false,
                Signature = new byte[1],
                TestId = "Test5"
            });

#endregion Parameter Validation

#region positive tests

            // HmacSha256 <-> HmacSha256Signature
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                RawBytes = rawBytes,
                SigningKey = Default.SymmetricSigningKey256,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha256Signature, rawBytes),
                TestId = "Test6"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256Signature,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha256, rawBytes),
                TestId = "Test7"
            });

            // HmacSha384 <-> HmacSha384Signature
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha384,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha384Signature, rawBytes),
                TestId = "Test8"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha384Signature,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha384, rawBytes),
                TestId = "Test9"
            });

            // HmacSha512 <-> HmacSha512Signature
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha512,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha512Signature, rawBytes),
                TestId = "Test10"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha512Signature,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha512, rawBytes),
                TestId = "Test11"
            });

            // JsonWebKey
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                SigningKey = KM.JsonWebKeySymmetric256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(KM.JsonWebKeySymmetric256, SA.HmacSha256Signature, rawBytes),
                TestId = "Test11",
            });

#endregion positive tests

#region negative tests

            // different algorithm
            // HmacSha256 -> HmacSha384
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                ExpectedException = EE.NoExceptionExpected,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha384, rawBytes),
                TestId = "Test12",
            });

            // HmacSha256 -> HmacSha512
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha512, rawBytes),
                TestId = "Test13",
            });

            // HmacSha384 -> HmacSha512
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha384,
                SigningKey = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha512, rawBytes),
                TestId = "Test14",
            });

            // Default.SymmetricSigningKey256 -> NotDefault.SymmetricSigningKey256
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                SigningKey = NotDefault.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha256, rawBytes),
                TestId = "Test15"
            });

            // Default.SymmetricSigningKey256 -> Default.SymmetricSigningKey384
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                SigningKey = Default.SymmetricSigningKey384,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SA.HmacSha384, rawBytes),
                TestId = "Test16",
            });

            // Default.SymmetricSigningKey384 -> NotDefault.SymmetricSigningKey384
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha384,
                SigningKey = NotDefault.SymmetricSigningKey384,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey384, SA.HmacSha384, rawBytes),
                TestId = "Test17"
            });

            // Default.SymmetricSigningKey384 -> Default.SymmetricSigningKey512
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha384,
                SigningKey = NotDefault.SymmetricSigningKey384,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey384, SA.HmacSha384, rawBytes),
                TestId = "Test18"
            });

            // Default.SymmetricSigningKey512 -> NoDefault.SymmetricSigningKey512
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha512,
                SigningKey = NotDefault.SymmetricSigningKey512,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey512, SA.HmacSha512, rawBytes),
                TestId = "Test19"
            });

            // Default.SymmetricSigningKey512 -> Default.SymmetricSigningKey1024
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha512,
                SigningKey = NotDefault.SymmetricSigningKey1024,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey1024, SA.HmacSha512, rawBytes),
                TestId = "Test20"
            });

            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                SigningKey = KM.JsonWebKeySymmetric256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(KM.JsonWebKeySymmetric256_2, SA.HmacSha256, rawBytes),
                TestId = "Test21",
            });

#endregion  negative tests

            return theoryData;
        }

        private static byte[] GetSignatureFromSymmetricKey(SecurityKey key, string algorithm, byte[] rawBytes)
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
            return provider.Sign(rawBytes);
        }

        [Theory, MemberData(nameof(KeyDisposeData))]
        public void SignatureProviderDispose_Test(string testId, SecurityKey securityKey, string algorithm, ExpectedException ee)
        {
            try
            {
                var jsonWebKey = securityKey as JsonWebKey;
                var symmetricSecurityKey = securityKey as SymmetricSecurityKey;

                if (symmetricSecurityKey != null || jsonWebKey?.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    SymmetricProviderDispose(testId, securityKey, algorithm, ee);
                else
                    AsymmetricProviderDispose(testId, securityKey, algorithm, ee);

                var bytes = new byte[1024];
                var provider = securityKey.CryptoProviderFactory.CreateForSigning(securityKey, algorithm);
                var signature = provider.Sign(bytes);
                securityKey.CryptoProviderFactory.ReleaseSignatureProvider(provider);

                provider = securityKey.CryptoProviderFactory.CreateForSigning(securityKey, algorithm);
                signature = provider.Sign(bytes);
                securityKey.CryptoProviderFactory.ReleaseSignatureProvider(provider);

                provider = securityKey.CryptoProviderFactory.CreateForVerifying(securityKey, algorithm);
                provider.Verify(bytes, signature);

                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        private void AsymmetricProviderDispose(string testId, SecurityKey securityKey, string algorithm, ExpectedException ee)
        {
            try
            {
                var bytes = new byte[256];
                var asymmetricProvider = new AsymmetricSignatureProvider(securityKey, algorithm, true);
                var signature = asymmetricProvider.Sign(bytes);
                asymmetricProvider.Dispose();

                asymmetricProvider = new AsymmetricSignatureProvider(securityKey, algorithm, true);
                signature = asymmetricProvider.Sign(bytes);
                asymmetricProvider.Dispose();

                asymmetricProvider = new AsymmetricSignatureProvider(securityKey, algorithm, false);
                asymmetricProvider.Verify(bytes, signature);

                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        private void SymmetricProviderDispose(string testId, SecurityKey securityKey, string algorithm, ExpectedException ee)
        {
            try
            {
                var bytes = new byte[256];
                var symmetricProvider = new SymmetricSignatureProvider(securityKey, algorithm);
                var signature = symmetricProvider.Sign(bytes);
                symmetricProvider.Dispose();

                symmetricProvider = new SymmetricSignatureProvider(securityKey, algorithm);
                signature = symmetricProvider.Sign(bytes);
                symmetricProvider.Dispose();

                symmetricProvider = new SymmetricSignatureProvider(securityKey, algorithm);
                symmetricProvider.Verify(bytes, signature);

                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, SecurityKey, string, ExpectedException> KeyDisposeData()
        {
            var theoryData = new TheoryData<string, SecurityKey, string, ExpectedException>();

#if NET452
            theoryData.Add(
                "Test1",
                new RsaSecurityKey(new RSACryptoServiceProvider(2048)),
                SA.RsaSha256,
                EE.NoExceptionExpected
            );
#endif
            theoryData.Add(
                "Test2",
                new RsaSecurityKey(KM.RsaParameters_2048),
                SA.RsaSha256,
                EE.NoExceptionExpected
            );

            theoryData.Add(
                "Test3",
                KM.JsonWebKeyRsa256,
                SA.RsaSha256,
                EE.NoExceptionExpected
            );

            theoryData.Add(
                "Test4",
                KM.JsonWebKeyEcdsa256,
                SA.EcdsaSha256,
                EE.NoExceptionExpected
            );

            theoryData.Add(
                "Test5",
                KM.Ecdsa256Key,
                SA.EcdsaSha256,
                EE.NoExceptionExpected
            );

            theoryData.Add(
                "Test6",
                KM.SymmetricSecurityKey2_256,
                SA.HmacSha256,
                EE.NoExceptionExpected
            );

            return theoryData;
        }

        [Theory, MemberData(nameof(SignatureTheoryData))]
        public void SignatureTampering(SignatureProviderTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureTampering", theoryData);
            var copiedSignature = theoryData.Signature.CloneByteArray();
            for (int i = 0; i < theoryData.Signature.Length; i++)
            {
                var originalB = theoryData.Signature[i];
                for (byte b = 0; b < byte.MaxValue; b++)
                {
                    // skip here as this will succeed
                    if (b == theoryData.Signature[i])
                        continue;

                    copiedSignature[i] = b;
                    Assert.False(theoryData.ProviderForVerifying.Verify(theoryData.RawBytes, copiedSignature), $"signature should not have verified: {theoryData.TestId} : {i} : {b} : {copiedSignature[i]}");

                    // reset so we move to next byte
                    copiedSignature[i] = originalB;
                }
            }

            Assert.True(theoryData.ProviderForVerifying.Verify(theoryData.RawBytes, copiedSignature), "Final check should have verified");
        }

        [Theory, MemberData(nameof(SignatureTheoryData))]
        public void SignatureTruncation(SignatureProviderTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureTruncation", theoryData);
            for (int i = 0; i < theoryData.Signature.Length - 1; i++)
            {
                var truncatedSignature = new byte[i + 1];
                Array.Copy(theoryData.Signature, truncatedSignature, i + 1);
                Assert.False(theoryData.ProviderForVerifying.Verify(theoryData.RawBytes, truncatedSignature), $"signature should not have verified: {theoryData.TestId} : {i}");
            }

            Assert.True(theoryData.ProviderForVerifying.Verify(theoryData.RawBytes, theoryData.Signature), "Final check should have verified");
        }

        public static TheoryData<SignatureProviderTheoryData> SignatureTheoryData()
        {
            var theoryData = new TheoryData<SignatureProviderTheoryData>();

            var rawBytes = Guid.NewGuid().ToByteArray();
            var asymmetricProvider = new AsymmetricSignatureProvider(KM.DefaultX509Key_2048, SA.RsaSha256, true);
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.RsaSha256,
                First = true,
                SigningKey = KM.DefaultX509Key_2048,
                ProviderForVerifying = asymmetricProvider,
                RawBytes = rawBytes,
                Signature = asymmetricProvider.Sign(rawBytes),
                TestId = SA.RsaSha256
            });

            var asymmetricProvider2 = new AsymmetricSignatureProvider(KM.Ecdsa256Key, SA.EcdsaSha256, true);
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.EcdsaSha256,
                SigningKey = KM.Ecdsa256Key,
                ProviderForVerifying = asymmetricProvider,
                RawBytes = rawBytes,
                Signature = asymmetricProvider.Sign(rawBytes),
                TestId = SA.EcdsaSha256
            });

            var symmetricProvider = new SymmetricSignatureProvider(KM.SymmetricSecurityKey2_256, SA.HmacSha256);
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha256,
                SigningKey = KM.SymmetricSecurityKey2_256,
                ProviderForVerifying = symmetricProvider,
                RawBytes = rawBytes,
                Signature = symmetricProvider.Sign(rawBytes),
                TestId = SA.HmacSha256
            });

            var symmetricProvider2 = new SymmetricSignatureProvider(KM.SymmetricSecurityKey2_512, SA.HmacSha512);
            theoryData.Add(new SignatureProviderTheoryData
            {
                SigningAlgorithm = SA.HmacSha512,
                SigningKey = KM.SymmetricSecurityKey2_512,
                ProviderForVerifying = symmetricProvider2,
                RawBytes = rawBytes,
                Signature = symmetricProvider2.Sign(rawBytes),
                TestId = SA.HmacSha512
            });

            return theoryData;
        }
    }

    public class CryptoProviderFactoryTheoryData : TheoryDataBase
    {
        public CryptoProviderFactoryTheoryData() { }

        public CryptoProviderFactoryTheoryData(string testId, string algorithm, SecurityKey signingKey, SecurityKey validatingKey, ExpectedException expectedException = null)
        {
            SigningAlgorithm = algorithm;
            SigningKey = signingKey;
            VerifyingKey = validatingKey;
            ExpectedException = expectedException ?? EE.NoExceptionExpected;
            TestId = testId;
        }

        public CryptoProviderFactory CryptoProviderFactory { get; set; } = CryptoProviderFactory.Default;

        public string SigningAlgorithm { get; set; }

        public SecurityKey SigningKey { get; set; }

        public override string ToString()
        {
            return TestId + ", " + SigningAlgorithm + ", " + SigningKey;
        }

        public string VerifyingAlgorithm { get; set; }

        public SecurityKey VerifyingKey { get; set; }

        public bool WillCreateSignatures { get; set; } = false;
    }

    public class SignatureProviderTheoryData : CryptoProviderFactoryTheoryData
    {
        public SignatureProviderTheoryData() { }

        public SignatureProviderTheoryData(string testId, string signingAlgorithm, string verifyingAlgorithm, SecurityKey signingKey, SecurityKey verifyingKey, EE expectedException = null)
        {
            SigningAlgorithm = signingAlgorithm;
            VerifyingAlgorithm = verifyingAlgorithm;
            SigningKey = signingKey;
            VerifyingKey = verifyingKey;
            ExpectedException = expectedException ?? EE.NoExceptionExpected;
            TestId = testId;
        }

        public SignatureProvider ProviderForVerifying { get; set; }

        public byte[] RawBytes { get; set; }

        public bool ShouldVerify { get; set; }

        public byte[] Signature { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
