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

using System.Collections.Generic;
using System.Reflection;
using Xunit;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Logging.Tests
{
    namespace Microsoft.IdentityModel.Logging.Tests
    {
        public class ExceptionTests
        {
            [Fact]
            public void CheckCustomExceptions()
            {
                var assemblies = new List<Assembly>()
                {
                    typeof(OpenIdConnectProtocolException).Assembly,
                    typeof(WsFederationException).Assembly,
                    typeof(SecurityTokenException).Assembly,
                    typeof(SamlSecurityTokenException).Assembly,
                    typeof(Saml2SecurityTokenException).Assembly,
                    typeof(XmlException).Assembly,
                };

                foreach (var assembly in assemblies)
                {
                    foreach (var t in assembly.GetTypes())
                    {
                        if (t.BaseType != null && t.BaseType.Name.Equals("Exception"))
                            Assert.True(LogHelper.IsCustomException(t.FullName));
                    }
                }
            }
        }
    }
}
