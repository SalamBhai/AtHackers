using System.Net;
using AtHackers.Abstractions;

namespace AtHackers.Exceptions
{
    public class ValueCannotBeNullException : CustomException
    {
        public ValueCannotBeNullException(string message = @"The Expected Value 
         Cannot Be Null. Application Stopped With Error Code:500", HttpStatusCode statusCode = HttpStatusCode.InternalServerError) : 
        base(message, statusCode)
        {
        }
    }
}