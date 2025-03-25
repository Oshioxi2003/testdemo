using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Flic.Server.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Articles",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Title = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SectionId = table.Column<int>(type: "int", nullable: false),
                    ImagePath = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ArticleAbstract = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ArticleContent = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreateDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                    UpdateDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Articles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetRoles",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    NormalizedName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUsers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    UserName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    NormalizedUserName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    NormalizedEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    EmailConfirmed = table.Column<bool>(type: "bit", nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SecurityStamp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PhoneNumber = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PhoneNumberConfirmed = table.Column<bool>(type: "bit", nullable: false),
                    TwoFactorEnabled = table.Column<bool>(type: "bit", nullable: false),
                    LockoutEnd = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LockoutEnabled = table.Column<bool>(type: "bit", nullable: false),
                    AccessFailedCount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DangkyTH03s",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    HovaDem = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Ten = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    GioiTinh = table.Column<int>(type: "int", nullable: false),
                    NgaySinh = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    NoiSinh_Tinh = table.Column<int>(type: "int", nullable: false),
                    DanToc = table.Column<int>(type: "int", nullable: false),
                    CCCD = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CCCD_NgayCap = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CCCD_NoiCap = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DienThoai = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DiaChi = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Email = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DKOnThi = table.Column<int>(type: "int", nullable: false),
                    LePhiThi = table.Column<int>(type: "int", nullable: true),
                    LePhiOn = table.Column<int>(type: "int", nullable: true),
                    DiaDiemThi = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DotThi = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Trangthai = table.Column<int>(type: "int", nullable: false),
                    Lock = table.Column<bool>(type: "bit", nullable: false),
                    MaSinhvien = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KhoahocID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KhoaID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    NganhID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LopID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DuDKThi = table.Column<bool>(type: "bit", nullable: false),
                    SoBD = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PhongThi = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CaThi = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Taikhoan = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Matkhau = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SoPhach = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DiemLT = table.Column<double>(type: "float", nullable: true),
                    DiemTH = table.Column<double>(type: "float", nullable: true),
                    Ketqua = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SoChungChi = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SoVaoSo = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    NgayTao = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NgaySua = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Ghichu = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    guid = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentSuccess = table.Column<bool>(type: "bit", nullable: true),
                    PaymentMethod = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentOrderDescription = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentOrderId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentTransactionId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentToken = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    VnPayResponseCode = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DangkyTH03s", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Diemthis",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Diemthis", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DKHocs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    HovaDem = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Ten = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    GioiTinh = table.Column<int>(type: "int", nullable: true),
                    CCCD = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DienThoai = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DiaChi = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Email = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    MaSinhvien = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KhoahocID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KhoaID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    NganhID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LopID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CourseId = table.Column<int>(type: "int", nullable: false),
                    Hocphi = table.Column<int>(type: "int", nullable: true),
                    DaThanhtoan = table.Column<int>(type: "int", nullable: true),
                    NgayThanhtoan = table.Column<DateTime>(type: "datetime2", nullable: true),
                    TTGiaodich = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    NgayTao = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NgaySua = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Ghichu = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Trangthai = table.Column<int>(type: "int", nullable: false),
                    guid = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentSuccess = table.Column<bool>(type: "bit", nullable: true),
                    PaymentMethod = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentOrderDescription = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentOrderId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentTransactionId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PaymentToken = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    VnPayResponseCode = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DKHocs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DMDantocs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DMDantocs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DMTinhs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DMTinhs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Dotthis",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    NgayThi = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Phithi = table.Column<int>(type: "int", nullable: true),
                    PhiOn = table.Column<int>(type: "int", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Dotthis", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Khoahocs",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Khoahocs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Khoanthus",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MaLoaiKhoanThu = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    KhoahocID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    NganhID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KyThanhToan = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SoTien = table.Column<double>(type: "float", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Khoanthus", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "Khoas",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Khoas", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "KyThanhtoans",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    LoaiKhoanthu = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Trangthai = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KyThanhtoans", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LoaiKhoanthus",
                columns: table => new
                {
                    MaLoaiKhoanThu = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    MoTa = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LoaiKhoanthus", x => x.MaLoaiKhoanThu);
                });

            migrationBuilder.CreateTable(
                name: "LoaiLophocs",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    TenLop = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Trangthai = table.Column<int>(type: "int", nullable: false),
                    guid = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LoaiLophocs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LogModels",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Username = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Password = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LogModels", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "Lophocs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    LoaiLop = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TenLop = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Mota = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ChiTiet = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ImagePath = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Hocphi = table.Column<int>(type: "int", nullable: false),
                    Trangthai = table.Column<int>(type: "int", nullable: false),
                    QRActive = table.Column<bool>(type: "bit", nullable: true),
                    VNPAYActive = table.Column<bool>(type: "bit", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Lophocs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Lops",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    KhoaID = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    KhoahocID = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    NganhID = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Trangthai = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Lops", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Nganhs",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    KhoaId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Nganhs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PhongKTXs",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Trangthai = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PhongKTXs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RequestGachNos",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    requestId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    providerId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    merchantId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    primaryKeyId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    custCode = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    custType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    custName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    address = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    birthday = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    phoneNo = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    idCard = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor1 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor2 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor3 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor4 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor5 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    bankTransactionId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    responseCode = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    responseDesc = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    transTime = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    channel = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    signature = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    items = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    timeUpdate = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RequestGachNos", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "RequestVanTins",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    requestId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    providerId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    merchantId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    custType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    custCode = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    channel = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    signature = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    timeRequest = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RequestVanTins", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "ResponseGachNos",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    requestId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    providerId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    merchantId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    confirmTransactionId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    transTime = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    responseCode = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    responseDesc = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfo = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    signature = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ResponseGachNos", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "ResponseItems",
                columns: table => new
                {
                    order = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    code = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    content = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    amount = table.Column<double>(type: "float", nullable: false),
                    currency = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    note = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ResponseItems", x => x.order);
                });

            migrationBuilder.CreateTable(
                name: "ResponseVanTins",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    requestId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    providerId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    merchantId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    transTime = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    custType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    custCode = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    custName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    address = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    birthday = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor1 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor2 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    addInfor3 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    responseCode = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    responseDesc = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    signature = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    primaryKeyId = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    items = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ResponseVanTins", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "Sections",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sections", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SinhvienPhongs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    PhongId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SinhvienId = table.Column<int>(type: "int", nullable: false),
                    Trangthai = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SinhvienPhongs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Students",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MaSV = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    HoDem = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Ten = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Ngaysinh = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KhoahocID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    KhoaID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    NganhID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LopID = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Email = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DienThoai = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CCCD = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SoNH = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SoTK = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Doituong = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Trangthai = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Students", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "StudentStatuses",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StudentStatuses", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TAICHINH_DuTruKP",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MaNhom = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    MaMucChi = table.Column<int>(type: "int", nullable: true),
                    TenMucChi = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DienGiai = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SoTien = table.Column<long>(type: "bigint", nullable: false),
                    MaDonVi = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Nam = table.Column<int>(type: "int", nullable: false),
                    NgayTao = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NgaySua = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TAICHINH_DuTruKP", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TAICHINH_MucChi",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    TenMuc = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    NhomMuc = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DoiTuong = table.Column<int>(type: "int", nullable: false),
                    MaTongHop = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TAICHINH_MucChi", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TAICHINH_NhomMuc",
                columns: table => new
                {
                    MaNhom = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    TenNhom = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TAICHINH_NhomMuc", x => x.MaNhom);
                });

            migrationBuilder.CreateTable(
                name: "ThuTiens",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    SinhVienID = table.Column<int>(type: "int", nullable: true),
                    LoaiKhoanthuID = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    KyThanhToan = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SoTien = table.Column<double>(type: "float", nullable: true),
                    NgayTao = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NgayThanhToan = table.Column<DateTime>(type: "datetime2", nullable: true),
                    TrangThai = table.Column<int>(type: "int", nullable: true),
                    ThanhtoanReqId = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThuTiens", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "Tin03_Trangthais",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tin03_Trangthais", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetRoleClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    RoleId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ClaimType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ClaimValue = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ClaimType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ClaimValue = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetUserClaims_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserLogins",
                columns: table => new
                {
                    LoginProvider = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ProviderKey = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ProviderDisplayName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserLogins", x => new { x.LoginProvider, x.ProviderKey });
                    table.ForeignKey(
                        name: "FK_AspNetUserLogins_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserRoles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    RoleId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserTokens",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    LoginProvider = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Value = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                    table.ForeignKey(
                        name: "FK_AspNetUserTokens_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "11ec8170-fceb-4a8e-8fb1-15463c2aa3a2", "078c0bfe-50fc-4f67-b57b-55efb0816952", "Manager", "MANAGER" },
                    { "28af4c4a-84cc-4d35-87a7-c5b12c4b9012", "e6b7414d-007f-43d8-b9fd-0827eb8f261d", "Admin", "ADMIN" },
                    { "5198c87e-b597-4837-b21d-079d91736800", "cf6d08a4-2df8-4a30-ae77-2391ae83451f", "User", "USER" },
                    { "56ded522-0cc7-4e5a-b5d0-9e8c956b621e", "05ce2622-b804-4dba-8d76-92f5b4d7f077", "Teacher", "TEACHER" },
                    { "ce1cc22a-0514-4820-89fa-d3d679359547", "b56d750d-6c7c-4506-b97f-39a3e2d32ea4", "Student", "STUDENT" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleClaims_RoleId",
                table: "AspNetRoleClaims",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "AspNetRoles",
                column: "NormalizedName",
                unique: true,
                filter: "[NormalizedName] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserClaims_UserId",
                table: "AspNetUserClaims",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserLogins_UserId",
                table: "AspNetUserLogins",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserRoles_RoleId",
                table: "AspNetUserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "AspNetUsers",
                column: "NormalizedUserName",
                unique: true,
                filter: "[NormalizedUserName] IS NOT NULL");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Articles");

            migrationBuilder.DropTable(
                name: "AspNetRoleClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserLogins");

            migrationBuilder.DropTable(
                name: "AspNetUserRoles");

            migrationBuilder.DropTable(
                name: "AspNetUserTokens");

            migrationBuilder.DropTable(
                name: "DangkyTH03s");

            migrationBuilder.DropTable(
                name: "Diemthis");

            migrationBuilder.DropTable(
                name: "DKHocs");

            migrationBuilder.DropTable(
                name: "DMDantocs");

            migrationBuilder.DropTable(
                name: "DMTinhs");

            migrationBuilder.DropTable(
                name: "Dotthis");

            migrationBuilder.DropTable(
                name: "Khoahocs");

            migrationBuilder.DropTable(
                name: "Khoanthus");

            migrationBuilder.DropTable(
                name: "Khoas");

            migrationBuilder.DropTable(
                name: "KyThanhtoans");

            migrationBuilder.DropTable(
                name: "LoaiKhoanthus");

            migrationBuilder.DropTable(
                name: "LoaiLophocs");

            migrationBuilder.DropTable(
                name: "LogModels");

            migrationBuilder.DropTable(
                name: "Lophocs");

            migrationBuilder.DropTable(
                name: "Lops");

            migrationBuilder.DropTable(
                name: "Nganhs");

            migrationBuilder.DropTable(
                name: "PhongKTXs");

            migrationBuilder.DropTable(
                name: "RequestGachNos");

            migrationBuilder.DropTable(
                name: "RequestVanTins");

            migrationBuilder.DropTable(
                name: "ResponseGachNos");

            migrationBuilder.DropTable(
                name: "ResponseItems");

            migrationBuilder.DropTable(
                name: "ResponseVanTins");

            migrationBuilder.DropTable(
                name: "Sections");

            migrationBuilder.DropTable(
                name: "SinhvienPhongs");

            migrationBuilder.DropTable(
                name: "Students");

            migrationBuilder.DropTable(
                name: "StudentStatuses");

            migrationBuilder.DropTable(
                name: "TAICHINH_DuTruKP");

            migrationBuilder.DropTable(
                name: "TAICHINH_MucChi");

            migrationBuilder.DropTable(
                name: "TAICHINH_NhomMuc");

            migrationBuilder.DropTable(
                name: "ThuTiens");

            migrationBuilder.DropTable(
                name: "Tin03_Trangthais");

            migrationBuilder.DropTable(
                name: "AspNetRoles");

            migrationBuilder.DropTable(
                name: "AspNetUsers");
        }
    }
}
