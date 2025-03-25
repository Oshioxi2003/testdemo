using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class VnPayService : IVnPayService
    {
        private readonly IConfiguration _configuration;
        private readonly IDKHoc _IDKHoc;
        public VnPayService(IConfiguration configuration, IDKHoc dkhoc)
        {
            _configuration = configuration;
            _IDKHoc = dkhoc;
        }
        public string CreatePaymentUrl(PaymentInformationModel model, HttpContext context)
        {
            var timeZoneById = TimeZoneInfo.FindSystemTimeZoneById(_configuration["TimeZoneId"]);
            var timeNow = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, timeZoneById);
            var tick = DateTime.Now.Ticks.ToString();
            var pay = new VnPayLibrary();
            var urlCallBack = _configuration["PaymentCallBack:ReturnUrl"];

            pay.AddRequestData("vnp_Version", _configuration["Vnpay:Version"]);
            pay.AddRequestData("vnp_Command", _configuration["Vnpay:Command"]);
            pay.AddRequestData("vnp_TmnCode", _configuration["Vnpay:TmnCode"]);
            pay.AddRequestData("vnp_Amount", ((int)model.Amount * 100).ToString());
            pay.AddRequestData("vnp_CreateDate", timeNow.ToString("yyyyMMddHHmmss"));
            pay.AddRequestData("vnp_CurrCode", _configuration["Vnpay:CurrCode"]);
            pay.AddRequestData("vnp_IpAddr", pay.GetIpAddress(context));
            pay.AddRequestData("vnp_Locale", _configuration["Vnpay:Locale"]);
            pay.AddRequestData("vnp_OrderInfo", $"{model.OrderId} {model.Name} {model.OrderDescription} {model.Amount}");
            pay.AddRequestData("vnp_OrderType", model.OrderType);
            pay.AddRequestData("vnp_ReturnUrl", urlCallBack);
            //pay.AddRequestData("vnp_TxnRef", tick);
            pay.AddRequestData("vnp_TxnRef", model.OrderId);
            //Cap nhat thong tin thanh toan
            //DKHoc tmp = _IDKHoc.Get(model.OrderId);
            //tmp.vnp_TxnRef = tick;
            //_IDKHoc.Update(tmp);
            //
            var paymentUrl =
                pay.CreateRequestUrl(_configuration["Vnpay:BaseUrl"], _configuration["Vnpay:HashSecret"]);

            return paymentUrl;
        }

        public PaymentResponseModel PaymentExecute(IQueryCollection collections)
        {
            var pay = new VnPayLibrary();
            var response = pay.GetFullResponseData(collections, _configuration["Vnpay:HashSecret"]);

            return response;
        }
        public PaymentResponseModel GetFullResponseData1(IQueryCollection collection, string hashSecret)
        {
            var vnPay = new VnPayLibrary();

            foreach (var (key, value) in collection)
            {
                if (!string.IsNullOrEmpty(key) && key.StartsWith("vnp_"))
                {
                    vnPay.AddResponseData(key, value);
                }
            }

            //var orderId = Convert.ToInt64(vnPay.GetResponseData("vnp_TxnRef"));
            string orderId = vnPay.GetResponseData("vnp_TxnRef");
            var vnPayTranId = Convert.ToInt64(vnPay.GetResponseData("vnp_TransactionNo"));
            var vnpResponseCode = vnPay.GetResponseData("vnp_ResponseCode");
            var vnpSecureHash =
                collection.FirstOrDefault(k => k.Key == "vnp_SecureHash").Value; //hash của dữ liệu trả về
            var orderInfo = vnPay.GetResponseData("vnp_OrderInfo");

            var checkSignature =
                vnPay.ValidateSignature(vnpSecureHash, hashSecret); //check Signature

            if (!checkSignature)
                return new PaymentResponseModel()
                {
                    Success = false
                };
            
            PaymentResponseModel rs = new PaymentResponseModel()
            {
                Success = true,
                PaymentMethod = "VnPay",
                OrderDescription = orderInfo,
                OrderId = orderId.ToString(),
                PaymentId = vnPayTranId.ToString(),
                TransactionId = vnPayTranId.ToString(),
                Token = vnpSecureHash,
                VnPayResponseCode = vnpResponseCode
            };
            //
            //DKHoc tmp = _IDKHoc.GetGuid(orderId);
            //tmp.Success = rs.Success;
            //tmp.PaymentMethod = rs.PaymentMethod;
            //tmp.OrderDescription = rs.OrderDescription;
            //tmp.PaymentId = rs.PaymentId;
            //tmp.TransactionId = rs.TransactionId;
            //tmp.Token = rs.Token;
            //tmp.VnPayResponseCode = rs.VnPayResponseCode;

            //_IDKHoc.Update(tmp);
            //
            return rs;
        }
    }
}
