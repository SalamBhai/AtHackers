using AtHackers.Exceptions;
using AtHackers.Hashers;
namespace AtHackers.Unifier
{
    ///<summary>
    /// Generates secured hashes using the .NET Cryptograpghy API and the Bcrypt.NET library 
    ///which provides developers with variant options for generation of secured hash password and also for validation.
    ///</summary>
    public class AtHackerHashProvider
    {
        /// <param name="PasswordToHash">The plain input for which a secured hash is generated.</param>
        /// <param name="HashAlgorithm">The hash algorithm to be used for the generation of the secured hash.
        ///if not specified, the library uses the BCRYPT hash function by default.</param>
        /// <param name="OnlyHashRequired">It specifies that the hash result to be generated should not be salted.
        ///If not specified the library generates a salted and secured hash password.</param>
        /// <param name="IsEnhancedBCrypt">It ensures that the hash generated is created through the BCRYPT EnhancedHashPassword method. 
        ///if overriden to be false the library generates an hash thorugh the hash password method. </param>
        /// <returns>Bool: <see langword="true"/>  Or <see langword="false"/> Generates secured hashes using the .NET Cryptograpghy API and the Bcrypt.NET library 
        ///which provides developers with variant options for generation of secured hash password.</returns>
        public static string GenerateHash(string PasswordToHash, string HashAlgorithm = "BCRYPT",
         bool OnlyHashRequired = false, bool IsEnhancedBCrypt = true)
        {
            var hash = "";
            #region  GenerateHash
            switch (HashAlgorithm.ToLower())
            {
                case "sha256":
                    hash = new SHA256HASHER().GenerateHash(PasswordToHash, OnlyHashRequired);
                    break;
                case "sha384":
                    hash = new SHA384HASHER().GenerateHash(PasswordToHash, OnlyHashRequired);
                    break;
                case "sha512":
                    hash = new SHA512HASHER().GenerateHash(PasswordToHash, OnlyHashRequired);
                    break;
                case "bcrypt":
                    hash = BCRYPTHASHER.GenerateHash(PasswordToHash, IsEnhancedBCrypt);
                    break;
                case "":
                    throw new ValueCannotBeNullException();

                default:
                    hash = BCRYPTHASHER.GenerateHash(PasswordToHash, IsEnhancedBCrypt);
                    break;
            }
            #endregion  GenerateHash
            return hash;
        }
       

        /// <param name="hashedPassword"> The Stored Hashed Password</param>
        /// <param name="plainInput"> The Plain Input Used For Storing The Password Hash</param>
        /// <param name="HashAlgorithm"> The Hash Algorithm For The Geneartion Of The Hash</param>
        /// <param name="IsEnhancedBCrypt">It ensures that the hash generated is created through the BCRYPT EnhancedHashPassword method. 
        ///if overriden to be false the library generates an hash thorugh the hash password method. </param>
        /// <returns>Bool: <see langword="true"/>  Or <see langword="false"/> It validates a stored user password which is generated using the Enhanced Bcrypt Algorithm or The SHA hash functions 
        ///Provided by the AtHackers library against a plain input text. 
        ///If not specified, a validation is made on the hashed password genrated with the BCRYPT hash function against the plain input text.</returns>

        public static bool ValidatePassword(string plainInput, string hashedPassword,
         string HashAlgorithm = "BCRYPT", bool IsEnhancedBCrypt = true)
        {
            var passwordStatus = false;
            #region ValidatePassword 
            switch (HashAlgorithm.ToLower())
            {
                case "sha256":
                    passwordStatus = new SHA256HASHER().ValidatePassword(plainInput, hashedPassword);
                    break;
                case "sha384":
                    passwordStatus = new SHA384HASHER().ValidatePassword(plainInput, hashedPassword);
                    break;
                case "sha512":
                    passwordStatus = new SHA512HASHER().ValidatePassword(plainInput, hashedPassword);
                    break;
                case "bcrypt":
                    passwordStatus = BCRYPTHASHER.ValidatePassword(plainInput, hashedPassword, IsEnhancedBCrypt);
                    break;
                case null:
                    throw new ValueCannotBeNullException();
                default:
                    passwordStatus = BCRYPTHASHER.ValidatePassword(plainInput, hashedPassword, IsEnhancedBCrypt);
                    break;
            }
            #endregion ValidatePassword
            return passwordStatus;
        }
    }
}