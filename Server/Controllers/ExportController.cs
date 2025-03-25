using System;
using System.Linq;
using System.Linq.Dynamic.Core;
using System.Data;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.IO;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Flic.Shared.Models;
using Flic.Server.Interfaces;
using ClosedXML.Excel;
using static System.Net.WebRequestMethods;
using Flic.Shared.Models.TaiChinh;
using DocumentFormat.OpenXml.InkML;
//using NPOI.SS.Format;

namespace ExportOperations
{
    public partial class ExportController : Controller
    {
        public IQueryable ApplyQuery<T>(IQueryable<T> items, IQueryCollection query = null) where T : class
        {
            if (query != null && items !=null && items.Count() > 0)
            {
                var filter = query.ContainsKey("$filter") ? query["$filter"].ToString() : null;
                if (!string.IsNullOrEmpty(filter))
                {
                    items = items.Where(filter);
                }

                if (query.ContainsKey("$orderBy"))
                {
                    items = items.OrderBy(query["$orderBy"].ToString());
                }

                if (query.ContainsKey("$expand"))
                {
                    var propertiesToExpand = query["$expand"].ToString().Split(',');
                    foreach (var p in propertiesToExpand)
                    {
                        items = items.Include(p);
                    }
                }

                if (query.ContainsKey("$skip"))
                {
                    items = items.Skip(int.Parse(query["$skip"].ToString()));
                }

                if (query.ContainsKey("$top"))
                {
                    items = items.Take(int.Parse(query["$top"].ToString()));
                }

                ////if (query.ContainsKey("$select"))
                ////{
                ////    return items.Select($"new ({query["$select"].ToString()})");
                ////}
            }

            return items;
        }

        public FileStreamResult ToCSV(IQueryable query, string fileName = null)
        {
            var columns = GetProperties(query.ElementType);

            var sb = new StringBuilder();

            foreach (var item in query)
            {
                var row = new List<string>();

                foreach (var column in columns)
                {
                    row.Add($"{GetValue(item, column.Key)}".Trim());
                }

                sb.AppendLine(string.Join(",", row.ToArray()));
            }


            var result = new FileStreamResult(new MemoryStream(UTF8Encoding.Default.GetBytes($"{string.Join(",", columns.Select(c => c.Key))}{System.Environment.NewLine}{sb.ToString()}")), "text/csv");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".csv";

            return result;
        }

        public FileStreamResult ToExcel(IQueryable query, string fileName = null)
        {
            var columns = GetProperties(query.ElementType);
            var stream = new MemoryStream();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);

                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = 1, Name = "Sheet1" };
                sheets.Append(sheet);

                workbookPart.Workbook.Save();

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());

                var headerRow = new Row();

                foreach (var column in columns)
                {
                    headerRow.Append(new Cell()
                    {
                        CellValue = new CellValue(column.Key),
                        DataType = new EnumValue<CellValues>(CellValues.String)
                    });
                }

                sheetData.AppendChild(headerRow);

                foreach (var item in query)
                {
                    var row = new Row();

                    foreach (var column in columns)
                    {
                        var value = GetValue(item, column.Key);
                        var stringValue = $"{value}".Trim();

                        var cell = new Cell();

                        var underlyingType = column.Value.IsGenericType &&
                            column.Value.GetGenericTypeDefinition() == typeof(Nullable<>) ?
                            Nullable.GetUnderlyingType(column.Value) : column.Value;

                        var typeCode = Type.GetTypeCode(underlyingType);

                        if (typeCode == TypeCode.DateTime)
                        {
                            if (stringValue != string.Empty)
                            {
                                cell.CellValue = new CellValue() { Text = DateTime.Parse(stringValue).ToOADate().ToString() };
                                cell.StyleIndex = (UInt32Value)1U;
                            }
                        }
                        else if (typeCode == TypeCode.Boolean)
                        {
                            cell.CellValue = new CellValue(stringValue.ToLower());
                            cell.DataType = new EnumValue<CellValues>(CellValues.Boolean);
                        }
                        else if (IsNumeric(typeCode))
                        {
                            cell.CellValue = new CellValue(stringValue);
                            cell.DataType = new EnumValue<CellValues>(CellValues.Number);
                        }
                        else
                        {
                            cell.CellValue = new CellValue(stringValue);
                            cell.DataType = new EnumValue<CellValues>(CellValues.String);
                        }

                        row.Append(cell);
                    }

                    sheetData.AppendChild(row);
                }


                workbookPart.Workbook.Save();
            }

            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        public Border GenerateBorder()
        {
            Border border2 = new Border();

            LeftBorder leftBorder2 = new LeftBorder() { Style = BorderStyleValues.Thin };
            Color color1 = new Color() { Indexed = (UInt32Value)64U };

            leftBorder2.Append(color1);

            RightBorder rightBorder2 = new RightBorder() { Style = BorderStyleValues.Thin };
            Color color2 = new Color() { Indexed = (UInt32Value)64U };

            rightBorder2.Append(color2);

            TopBorder topBorder2 = new TopBorder() { Style = BorderStyleValues.Thin };
            Color color3 = new Color() { Indexed = (UInt32Value)64U };

            topBorder2.Append(color3);

            BottomBorder bottomBorder2 = new BottomBorder() { Style = BorderStyleValues.Thin };
            Color color4 = new Color() { Indexed = (UInt32Value)64U };

            bottomBorder2.Append(color4);
            DiagonalBorder diagonalBorder2 = new DiagonalBorder();

            border2.Append(leftBorder2);
            border2.Append(rightBorder2);
            border2.Append(topBorder2);
            border2.Append(bottomBorder2);
            //border2.Append(diagonalBorder2);

            return border2;
        }
        public Fill GenerateFill()
        {
            Fill fill = new Fill();

            PatternFill patternFill = new PatternFill() { PatternType = PatternValues.Solid };
            ForegroundColor foregroundColor1 = new ForegroundColor() { Rgb = "FFFFFF00" };
            BackgroundColor backgroundColor1 = new BackgroundColor() { Indexed = (UInt32Value)64U };

            patternFill.Append(foregroundColor1);
            patternFill.Append(backgroundColor1);

            fill.Append(patternFill);

            return fill;
        }
        public uint InsertBorder(WorkbookPart workbookPart, Border border)
        {
            Borders borders = workbookPart.WorkbookStylesPart.Stylesheet.Elements<Borders>().First();
            borders.Append(border);
            return (uint)borders.Count++;
        }

        public uint InsertFill(WorkbookPart workbookPart, Fill fill)
        {
            Fills fills = workbookPart.WorkbookStylesPart.Stylesheet.Elements<Fills>().First();
            fills.Append(fill);
            return (uint)fills.Count++;
        }
        public uint InsertFont(WorkbookPart workbookPart, Font font)
        {
            Fonts fonts = workbookPart.WorkbookStylesPart.Stylesheet.Elements<Fonts>().First();
            
            return (uint)fonts.Count++;
        }
        public Cell GetCell(WorksheetPart workSheetPart, string cellAddress)
        {
            return workSheetPart.Worksheet.Descendants<Cell>()
                                        .SingleOrDefault(c => cellAddress.Equals(c.CellReference));
        }
        public CellFormat GetCellFormat(WorkbookPart workbookPart, uint styleIndex)
        {
            return workbookPart.WorkbookStylesPart.Stylesheet.Elements<CellFormats>().First().Elements<CellFormat>().ElementAt((int)styleIndex);
        }

        public uint InsertCellFormat(WorkbookPart workbookPart, CellFormat cellFormat)
        {
            CellFormats cellFormats = workbookPart.WorkbookStylesPart.Stylesheet.Elements<CellFormats>().First();
            cellFormats.Append(cellFormat);
            
            
            return (uint)cellFormats.Count++;
        }
        public void SetBorderAndFill(WorkbookPart workbookPart, WorksheetPart workSheetPart,string cellAddr, bool filled, bool border, HorizontalAlignmentValues ha, VerticalAlignmentValues va)
        {
            Cell cell = GetCell(workSheetPart, cellAddr);
            if (cell != null)
            {
                CellFormat cellFormat = cell.StyleIndex != null ? GetCellFormat(workbookPart, cell.StyleIndex).CloneNode(true) as CellFormat : new CellFormat();
                if (filled)
                    cellFormat.FillId = InsertFill(workbookPart, GenerateFill());
                if (border)
                    cellFormat.BorderId = InsertBorder(workbookPart, GenerateBorder());


                cellFormat.Alignment = new Alignment()
                {
                    Horizontal = ha, //HorizontalAlignmentValues.Center,
                    Vertical = va//VerticalAlignmentValues.Center
                };
                cell.StyleIndex = InsertCellFormat(workbookPart, cellFormat);
            }
            
            
        }
        public FileStreamResult DSPTToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "dsphongthi";
            var stream = new MemoryStream();
            var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                foreach (var pt in dsPhongthi)
                {
                    var dsCathi = list.Where(m => m.PhongThi == pt.PhongThi).DistinctBy(m => m.CaThi).ToList();
                    foreach (var c in dsCathi)
                    {
                        ///
                        var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                        worksheetPart.Worksheet = new Worksheet();
                        var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = pt.PhongThi + "_" + c.CaThi };
                        _sheetId++;
                        sheets.Append(sheet);

                        //workbookPart.Workbook.Save();

                        var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());
                        ///                                             

                        //add a row
                        Row firstRow = new Row();
                        firstRow.RowIndex = (UInt32)1;
                        //create a cell in C1 (the upper left most cell of the merged cells)
                        Cell dataCell = new Cell() { CellReference = "A1", CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };                        
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E1", CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)2;
                        dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E2", CellValue = new CellValue("Độc lập - Tự do - Hạnh phúc"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)3;
                        //dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        //firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E3", CellValue = new CellValue("..., ngày  tháng ... năm ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)5;                        
                        dataCell = new Cell() { CellReference = "A5", CellValue = new CellValue("DANH SÁCH PHÒNG THI"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)6;
                        dataCell = new Cell() { CellReference = "A6", CellValue = new CellValue("KỲ THI CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)7;
                        dataCell = new Cell() { CellReference = "A7", CellValue = new CellValue("Đợt thi...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)8;
                        dataCell = new Cell() { CellReference = "A8", CellValue = new CellValue("Phòng thi:" + pt.PhongThi), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D8", CellValue = new CellValue("Ngày thi: " ), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)9;                        
                        dataCell = new Cell() { CellReference = "D9", CellValue = new CellValue("Ca thi: " + c.CaThi + " Thời gian thi:"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)10;
                        dataCell = new Cell() { CellReference = "A10", CellValue = new CellValue("STT"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "B10", CellValue = new CellValue("SBD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "C10", CellValue = new CellValue("Số CCCD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D10", CellValue = new CellValue("Họ và tên"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "F10", CellValue = new CellValue("Ngày sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G10", CellValue = new CellValue("Giới tính"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "H10", CellValue = new CellValue("Bài thi"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "J10", CellValue = new CellValue("Ký nộp"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "K10", CellValue = new CellValue("Ghi chú"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)11;
                        dataCell = new Cell() { CellReference = "H11", CellValue = new CellValue("Lý thuyết"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "I11", CellValue = new CellValue("Thực hành"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        UInt32 hang = 12;
                        UInt32 startData = 12;
                        var dsThisinh = list.Where(m => m.PhongThi == pt.PhongThi).Where(m => m.CaThi == c.CaThi).ToList();
                        foreach (var ts in dsThisinh)
                        {
                            firstRow = new Row();
                            firstRow.RowIndex = hang;

                            dataCell = new Cell() { CellReference = "A"+hang.ToString(), CellValue = new CellValue((decimal)(hang-11)), DataType = new EnumValue<CellValues>(CellValues.Number) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "B" + hang.ToString(), CellValue = new CellValue(ts.SoBD), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "C" + hang.ToString(), CellValue = new CellValue(ts.CCCD), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "D" + hang.ToString(), CellValue = new CellValue(ts.HovaDem), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "E" + hang.ToString(), CellValue = new CellValue(ts.Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "F" + hang.ToString(), CellValue = new CellValue(ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            string gt = ts.GioiTinh != null && ts.GioiTinh == 0 ? "Nữ" : "Nam";
                            dataCell = new Cell() { CellReference = "G" + hang.ToString(), CellValue = new CellValue(gt), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);

                            hang = hang + 1;
                            sheetData.AppendChild(firstRow);
                            
                        }

                        //SetBorderAndFill(workbookPart, worksheetPart, "A" + startData.ToString()+"K" + hang.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        UInt32 ft1 = hang;
                        UInt32 ft2 = hang+1;
                        UInt32 ft3 = hang+2;

                        firstRow = new Row();
                        firstRow.RowIndex = ft1;
                        dataCell = new Cell() { CellReference = "A" + ft1.ToString(), CellValue = new CellValue("Tổng số:…...bài"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft2;
                        dataCell = new Cell() { CellReference = "A" + ft2.ToString(), CellValue = new CellValue("Giám thị 1"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D" + ft2.ToString(), CellValue = new CellValue("Giám thị 2"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G" + ft2.ToString(), CellValue = new CellValue("CHỦ TỊCH HỘI ĐỒNG THI"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft3;
                        dataCell = new Cell() { CellReference = "A" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        ////create a MergeCells class to hold each MergeCell
                        MergeCells mergeCells = new MergeCells();

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A"+ft1.ToString()+ ":K" + ft1.ToString())});

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft2.ToString() + ":C" + ft2.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D" + ft2.ToString() + ":F" + ft2.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + ft2.ToString() + ":K" + ft2.ToString()) });
                        SetBorderAndFill(workbookPart, worksheetPart, "A" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft3.ToString() + ":C" + ft3.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D" + ft3.ToString() + ":F" + ft3.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + ft3.ToString() + ":K" + ft3.ToString()) });

                        SetBorderAndFill(workbookPart, worksheetPart, "A" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);


                        //append a MergeCell to the mergeCells for each set of merged cells
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A1:D1") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E1:K1") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A2:D2") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E2:K2") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E3:K3") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A5:K5") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A6:K6") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A7:K7") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A8:C9") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D8:K8") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D9:K9") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A10:A11") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("B10:B11") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("C10:C11") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D10:E11") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("F10:F11") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("G10:G11") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("J10:J11") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("K10:K11") });

                        SetBorderAndFill(workbookPart, worksheetPart, "A1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E3", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A5", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A6", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A7", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        SetBorderAndFill(workbookPart, worksheetPart, "A10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "B10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "C10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "F10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "J10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "K10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "H11", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "I11", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        worksheetPart.Worksheet.InsertAfter(mergeCells, worksheetPart.Worksheet.Elements<SheetData>().First());
                    }
                }
                workbookPart.Workbook.Save();
            }
            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //
        public FileStreamResult DSLythuyetToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "danh sách thi lý thuyết";
            var stream = new MemoryStream();
            var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();
            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                foreach (var pt in dsPhongthi)
                {
                    var dsCathi = list.Where(m => m.PhongThi == pt.PhongThi).DistinctBy(m => m.CaThi).ToList();
                    foreach (var c in dsCathi)
                    {
                        ///
                        var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                        worksheetPart.Worksheet = new Worksheet();
                        var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = pt.PhongThi + "_" + c.CaThi };
                        _sheetId++;
                        sheets.Append(sheet);
                        var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());
                        
                        //add a row
                        Row firstRow = new Row();
                        firstRow.RowIndex = (UInt32)1;
                        //create a cell in C1 (the upper left most cell of the merged cells)
                        Cell dataCell = new Cell() { CellReference = "A1", CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E1", CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)2;
                        dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E2", CellValue = new CellValue("Độc lập - Tự do - Hạnh phúc"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)3;
                        //dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        //firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E3", CellValue = new CellValue("..., ngày  tháng ... năm ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)5;
                        dataCell = new Cell() { CellReference = "A5", CellValue = new CellValue("DANH SÁCH THÍ SINH DỰ THI TRẮC NGHIỆM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)6;
                        dataCell = new Cell() { CellReference = "A6", CellValue = new CellValue("KỲ THI CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)7;
                        dataCell = new Cell() { CellReference = "A7", CellValue = new CellValue("Đợt thi...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)8;
                        dataCell = new Cell() { CellReference = "A8", CellValue = new CellValue("Phòng thi:" + pt.PhongThi), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D8", CellValue = new CellValue("Ngày thi: "), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)9;
                        dataCell = new Cell() { CellReference = "D9", CellValue = new CellValue("Ca thi: " + c.CaThi + " Thời gian thi:"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)10;
                        dataCell = new Cell() { CellReference = "A10", CellValue = new CellValue("STT"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "B10", CellValue = new CellValue("SBD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "C10", CellValue = new CellValue("Số CCCD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D10", CellValue = new CellValue("Họ và tên"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "F10", CellValue = new CellValue("Ngày sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G10", CellValue = new CellValue("Giới tính"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "H10", CellValue = new CellValue("Số máy"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "I10", CellValue = new CellValue("Điểm"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "J10", CellValue = new CellValue("Ký nộp"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "K10", CellValue = new CellValue("Ghi chú"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        UInt32 hang = 11;
                        UInt32 startData = 11;
                        var dsThisinh = list.Where(m => m.PhongThi == pt.PhongThi).Where(m => m.CaThi == c.CaThi).ToList();
                        foreach (var ts in dsThisinh)
                        {
                            firstRow = new Row();
                            firstRow.RowIndex = hang;

                            dataCell = new Cell() { CellReference = "A" + hang.ToString(), CellValue = new CellValue((decimal)(hang - 10)), DataType = new EnumValue<CellValues>(CellValues.Number) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "B" + hang.ToString(), CellValue = new CellValue(ts.SoBD), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "C" + hang.ToString(), CellValue = new CellValue(ts.CCCD), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "D" + hang.ToString(), CellValue = new CellValue(ts.HovaDem), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "E" + hang.ToString(), CellValue = new CellValue(ts.Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "F" + hang.ToString(), CellValue = new CellValue(ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            string gt = ts.GioiTinh != null && ts.GioiTinh == 0 ? "Nữ" : "Nam";
                            dataCell = new Cell() { CellReference = "G" + hang.ToString(), CellValue = new CellValue(gt), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);

                            hang = hang + 1;
                            sheetData.AppendChild(firstRow);

                        }

                        UInt32 ft1 = hang;
                        UInt32 ft10 = hang +1;
                        UInt32 ft11 = hang +2 ;

                        UInt32 ft2 = hang + 3;
                        UInt32 ft3 = hang + 4;

                        firstRow = new Row();
                        firstRow.RowIndex = ft1;
                        dataCell = new Cell() { CellReference = "A" + ft1.ToString(), CellValue = new CellValue("Tổng số:…...bài"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft10;
                        dataCell = new Cell() { CellReference = "A" + ft10.ToString(), CellValue = new CellValue("Số thí sinh dự thi:………..Số thí sinh vắng……………"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft11;
                        dataCell = new Cell() { CellReference = "A" + ft11.ToString(), CellValue = new CellValue("Hoàn tất ghi nhận kết quả vào lúc…..giờ……phút, ngày……tháng…….năm………"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        firstRow = new Row();
                        firstRow.RowIndex = ft2;
                        dataCell = new Cell() { CellReference = "A" + ft2.ToString(), CellValue = new CellValue("Giám thị 1"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D" + ft2.ToString(), CellValue = new CellValue("Giám thị 2"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G" + ft2.ToString(), CellValue = new CellValue("TRƯỞNG BAN COI THI"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft3;
                        dataCell = new Cell() { CellReference = "A" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        ////create a MergeCells class to hold each MergeCell
                        MergeCells mergeCells = new MergeCells();

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft1.ToString() + ":K" + ft1.ToString()) });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft2.ToString() + ":C" + ft2.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D" + ft2.ToString() + ":F" + ft2.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + ft2.ToString() + ":K" + ft2.ToString()) });
                        SetBorderAndFill(workbookPart, worksheetPart, "A" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft3.ToString() + ":C" + ft3.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D" + ft3.ToString() + ":F" + ft3.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + ft3.ToString() + ":K" + ft3.ToString()) });

                        SetBorderAndFill(workbookPart, worksheetPart, "A" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        //append a MergeCell to the mergeCells for each set of merged cells
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A1:D1") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E1:K1") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A2:D2") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E2:K2") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E3:K3") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A5:K5") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A6:K6") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A7:K7") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A8:C9") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D8:K8") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D9:K9") });

                        SetBorderAndFill(workbookPart, worksheetPart, "A1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E3", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A5", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A6", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A7", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        SetBorderAndFill(workbookPart, worksheetPart, "A10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "B10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "C10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "F10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "J10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "K10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        
                        worksheetPart.Worksheet.InsertAfter(mergeCells, worksheetPart.Worksheet.Elements<SheetData>().First());
                    }
                }
                workbookPart.Workbook.Save();
            }

            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //
        public FileStreamResult DSThuchanhToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "danh sách thi thực hành";
            var stream = new MemoryStream();
            var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                foreach (var pt in dsPhongthi)
                {
                    var dsCathi = list.Where(m => m.PhongThi == pt.PhongThi).DistinctBy(m => m.CaThi).ToList();
                    foreach (var c in dsCathi)
                    {
                        ///
                        var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                        worksheetPart.Worksheet = new Worksheet();
                        var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = pt.PhongThi + "_" + c.CaThi };
                        _sheetId++;
                        sheets.Append(sheet);
                        var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());

                        //add a row
                        Row firstRow = new Row();
                        firstRow.RowIndex = (UInt32)1;
                        //create a cell in C1 (the upper left most cell of the merged cells)
                        Cell dataCell = new Cell() { CellReference = "A1", CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E1", CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)2;
                        dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E2", CellValue = new CellValue("Độc lập - Tự do - Hạnh phúc"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)3;
                        //dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        //firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E3", CellValue = new CellValue("..., ngày  tháng ... năm ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)5;
                        dataCell = new Cell() { CellReference = "A5", CellValue = new CellValue("DANH SÁCH THÍ SINH DỰ THI THỰC HÀNH"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)6;
                        dataCell = new Cell() { CellReference = "A6", CellValue = new CellValue("KỲ THI CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)7;
                        dataCell = new Cell() { CellReference = "A7", CellValue = new CellValue("Đợt thi...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)8;
                        dataCell = new Cell() { CellReference = "A8", CellValue = new CellValue("Phòng thi:" + pt.PhongThi), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D8", CellValue = new CellValue("Ngày thi: "), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)9;
                        dataCell = new Cell() { CellReference = "D9", CellValue = new CellValue("Ca thi: " + c.CaThi + " Thời gian thi:"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)10;
                        dataCell = new Cell() { CellReference = "A10", CellValue = new CellValue("STT"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "B10", CellValue = new CellValue("SBD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);                        
                        dataCell = new Cell() { CellReference = "C10", CellValue = new CellValue("Họ và tên"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "E10", CellValue = new CellValue("Ngày sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "F10", CellValue = new CellValue("Giới tính"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G10", CellValue = new CellValue("Số máy/Số bài"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "H10", CellValue = new CellValue("Dung lượng"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "I10", CellValue = new CellValue("Điểm"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "J10", CellValue = new CellValue("Ký nộp"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "K10", CellValue = new CellValue("Ghi chú"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        UInt32 hang = 11;
                        UInt32 startData = 11;
                        var dsThisinh = list.Where(m => m.PhongThi == pt.PhongThi).Where(m => m.CaThi == c.CaThi).ToList();
                        foreach (var ts in dsThisinh)
                        {
                            firstRow = new Row();
                            firstRow.RowIndex = hang;

                            dataCell = new Cell() { CellReference = "A" + hang.ToString(), CellValue = new CellValue((decimal)(hang - 10)), DataType = new EnumValue<CellValues>(CellValues.Number) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "B" + hang.ToString(), CellValue = new CellValue(ts.SoBD), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);                            
                            dataCell = new Cell() { CellReference = "C" + hang.ToString(), CellValue = new CellValue(ts.HovaDem), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "D" + hang.ToString(), CellValue = new CellValue(ts.Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = "E" + hang.ToString(), CellValue = new CellValue(ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);
                            string gt = ts.GioiTinh != null && ts.GioiTinh == 0 ? "Nữ" : "Nam";
                            dataCell = new Cell() { CellReference = "F" + hang.ToString(), CellValue = new CellValue(gt), DataType = new EnumValue<CellValues>(CellValues.String) };
                            firstRow.AppendChild(dataCell);

                            hang = hang + 1;
                            sheetData.AppendChild(firstRow);

                        }

                        UInt32 ft1 = hang;
                        UInt32 ft10 = hang + 1;
                        UInt32 ft11 = hang + 2;

                        UInt32 ft2 = hang + 3;
                        UInt32 ft3 = hang + 4;

                        firstRow = new Row();
                        firstRow.RowIndex = ft1;
                        dataCell = new Cell() { CellReference = "A" + ft1.ToString(), CellValue = new CellValue("Tổng số:…...bài"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft10;
                        dataCell = new Cell() { CellReference = "A" + ft10.ToString(), CellValue = new CellValue("Số thí sinh dự thi:………..Số thí sinh vắng……………"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft11;
                        dataCell = new Cell() { CellReference = "A" + ft11.ToString(), CellValue = new CellValue("Hoàn tất ghi nhận kết quả vào lúc…..giờ……phút, ngày……tháng…….năm………"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        firstRow = new Row();
                        firstRow.RowIndex = ft2;
                        dataCell = new Cell() { CellReference = "A" + ft2.ToString(), CellValue = new CellValue("Giám thị 1"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D" + ft2.ToString(), CellValue = new CellValue("Giám thị 2"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G" + ft2.ToString(), CellValue = new CellValue("TRƯỞNG BAN COI THI"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft3;
                        dataCell = new Cell() { CellReference = "A" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "D" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "G" + ft3.ToString(), CellValue = new CellValue("(Ký và ghi rõ họ tên)"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        ////create a MergeCells class to hold each MergeCell
                        MergeCells mergeCells = new MergeCells();

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft1.ToString() + ":K" + ft1.ToString()) });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft2.ToString() + ":C" + ft2.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D" + ft2.ToString() + ":F" + ft2.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + ft2.ToString() + ":K" + ft2.ToString()) });
                        SetBorderAndFill(workbookPart, worksheetPart, "A" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A" + ft3.ToString() + ":C" + ft3.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D" + ft3.ToString() + ":F" + ft3.ToString()) });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + ft3.ToString() + ":K" + ft3.ToString()) });

                        SetBorderAndFill(workbookPart, worksheetPart, "A" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "D" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G" + ft3.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        //append a MergeCell to the mergeCells for each set of merged cells
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A1:D1") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E1:K1") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A2:D2") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E2:K2") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("E3:K3") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A5:K5") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A6:K6") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A7:K7") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A8:C9") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D8:K8") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("D9:K9") });

                        SetBorderAndFill(workbookPart, worksheetPart, "A1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "E3", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A5", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A6", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A7", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        SetBorderAndFill(workbookPart, worksheetPart, "A10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "B10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "C10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        //SetBorderAndFill(workbookPart, worksheetPart, "D10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "F10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "G10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "J10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "K10", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        worksheetPart.Worksheet.InsertAfter(mergeCells, worksheetPart.Worksheet.Elements<SheetData>().First());
                    }
                }
                workbookPart.Workbook.Save();
            }
            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }

        /// <summary>
        /// 
        /// Export danh sách tài khoản cho hệ thống thi moodle
        /// </summary>
        /// <param name="list"></param>
        /// <returns></returns>

        public FileStreamResult DSTaikhoanToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "danh sách tài khoản";
            var stream = new MemoryStream();
            var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();



                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());

                var headerRow = new Row();

                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("username"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("password"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("firstname"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("lastname"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("email"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("idnumber"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("institution"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("department"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                

                sheetData.AppendChild(headerRow);

                int tt = 1;
                var dsThisinh = list.OrderBy(m=>m.SoBD).ToList();
                foreach (var ts in dsThisinh)
                {
                    var row = new Row();
                    var cell = new Cell();                    
                    cell.CellValue = new CellValue(ts.SoBD);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.Matkhau);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.DotThi +"_" + ts.CaThi + "_" + ts.PhongThi + "_" + ts.SoBD );
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.HovaDem + " " + ts.Ten + "_" + ts.NgaySinh);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.Email);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.SoBD);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.PhongThi);
                    cell.DataType = CellValues.String;
                    row.Append(cell);
                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.CaThi);
                    cell.DataType = CellValues.String;
                    row.Append(cell);


                    tt = tt + 1;
                    sheetData.AppendChild(row);
                }

                
                workbookPart.Workbook.Save();

            }
            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        /// <summary>
        /// Export danh sách phê duyệt kết quả
        /// </summary>
        /// <param name="list"></param>
        /// <returns></returns>
        public FileStreamResult Tinhoc03DsKQToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "Danh sách phê duyệt kết quả";
            var stream = new MemoryStream();
            //var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());

                var headerRow = new Row();
                // Header
                //add a row
                Row firstRow = new Row();
                firstRow.RowIndex = (UInt32)1;
                //create a cell in C1 (the upper left most cell of the merged cells)
                Cell dataCell = new Cell() { CellReference = "A1", CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F1", CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)2;
                dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F2", CellValue = new CellValue("Độc lập - Tự do - Hạnh phúc"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)3;
                //dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                //firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F3", CellValue = new CellValue("..., ngày  tháng ... năm ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)5;
                dataCell = new Cell() { CellReference = "A5", CellValue = new CellValue("DANH SÁCH KẾT QUẢ"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)6;
                dataCell = new Cell() { CellReference = "A6", CellValue = new CellValue("KỲ THI CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)7;
                dataCell = new Cell() { CellReference = "A7", CellValue = new CellValue("Đợt thi...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)8;
                dataCell = new Cell() { CellReference = "A8", CellValue = new CellValue("Kèm theo quyết định số: /QĐ-HVTTNVN ngày ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);
                //


                firstRow = new Row();
                firstRow.RowIndex = (UInt32)9;
                dataCell = new Cell() { CellReference = "A9", CellValue = new CellValue("STT"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "B9", CellValue = new CellValue("SBD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "C9", CellValue = new CellValue("Số CCCD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "D9", CellValue = new CellValue("Họ và tên"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F9", CellValue = new CellValue("Ngày sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "G9", CellValue = new CellValue("Giới tính"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "H9", CellValue = new CellValue("Nơi sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "I9", CellValue = new CellValue("Lý thuyết"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "J9", CellValue = new CellValue("Thực hành"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "K9", CellValue = new CellValue("Kết quả"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "L9", CellValue = new CellValue("Lớp"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);


                int tt = 1;
                UInt32 hang = 10;
                var dsThisinh = list.OrderBy(m => m.SoBD).ToList();
                foreach (var ts in dsThisinh)
                {
                    firstRow = new Row();
                    firstRow.RowIndex = hang;

                    dataCell = new Cell() { CellReference = "A" + hang.ToString(), CellValue = new CellValue((decimal)(hang - 9)), DataType = new EnumValue<CellValues>(CellValues.Number) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "B" + hang.ToString(), CellValue = new CellValue(ts.SoBD), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "C" + hang.ToString(), CellValue = new CellValue(ts.CCCD), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "D" + hang.ToString(), CellValue = new CellValue(ts.HovaDem), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "E" + hang.ToString(), CellValue = new CellValue(ts.Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "F" + hang.ToString(), CellValue = new CellValue(ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    
                    string gt = ts.GioiTinh != null && ts.GioiTinh == 0 ? "Nữ" : "Nam";
                    dataCell = new Cell() { CellReference = "G" + hang.ToString(), CellValue = new CellValue(gt), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    dataCell = new Cell() { CellReference = "H" + hang.ToString(), CellValue = new CellValue(ts.NoiSinh_Tinh_Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    if (ts.DiemLT != null)
                    {
                        dataCell = new Cell() { CellReference = "I" + hang.ToString(), CellValue = new CellValue(ts.DiemLT.Value), DataType = new EnumValue<CellValues>(CellValues.Number) };
                        firstRow.AppendChild(dataCell);
                    }
                    if (ts.DiemTH != null)
                    {
                        dataCell = new Cell() { CellReference = "J" + hang.ToString(), CellValue = new CellValue(ts.DiemTH.Value), DataType = new EnumValue<CellValues>(CellValues.Number) };
                        firstRow.AppendChild(dataCell);
                    }                        

                    dataCell = new Cell() { CellReference = "K" + hang.ToString(), CellValue = new CellValue(ts.Ketqua), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    dataCell = new Cell() { CellReference = "L" + hang.ToString(), CellValue = new CellValue(ts.LopID), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    

                    hang = hang + 1;
                    sheetData.AppendChild(firstRow);                    
                }
                firstRow = new Row();
                firstRow.RowIndex = hang;
                string s = "Danh sách gồm có " + dsThisinh.Count().ToString() + " thí sinh";
                dataCell = new Cell() { CellReference = "A" + hang.ToString(), CellValue = new CellValue(s), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);
                //
                MergeCells mergeCells = new MergeCells();
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A1:E1") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("F1:K1") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A2:E2") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("F2:K2") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("F3:K3") });

                mergeCells.Append(new MergeCell() { Reference = new StringValue("A5:K5") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A6:K6") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A7:K7") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A8:K8") });
                worksheetPart.Worksheet.InsertAfter(mergeCells, worksheetPart.Worksheet.Elements<SheetData>().First());
                //
                workbookPart.Workbook.Save();
            }

            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //
        /// <summary>
        /// Export danh sách cấp chứng chỉ
        /// </summary>
        /// <param name="list"></param>
        /// <returns></returns>
        public FileStreamResult Tinhoc03DSCapChungchiToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "Danh sách cấp chứng chỉ";
            var stream = new MemoryStream();
            //var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());

                var headerRow = new Row();
                // Header
                //add a row
                Row firstRow = new Row();
                firstRow.RowIndex = (UInt32)1;
                //create a cell in C1 (the upper left most cell of the merged cells)
                Cell dataCell = new Cell() { CellReference = "A1", CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F1", CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)2;
                dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F2", CellValue = new CellValue("Độc lập - Tự do - Hạnh phúc"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)3;
                //dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                //firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F3", CellValue = new CellValue("..., ngày  tháng ... năm ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)5;
                dataCell = new Cell() { CellReference = "A5", CellValue = new CellValue("DANH SÁCH"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)6;
                dataCell = new Cell() { CellReference = "A6", CellValue = new CellValue("CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)7;
                dataCell = new Cell() { CellReference = "A7", CellValue = new CellValue("Đợt thi...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)8;
                dataCell = new Cell() { CellReference = "A8", CellValue = new CellValue("Kèm theo quyết định số: /QĐ-HVTTNVN ngày ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);
                //


                firstRow = new Row();
                firstRow.RowIndex = (UInt32)9;
                dataCell = new Cell() { CellReference = "A9", CellValue = new CellValue("STT"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "B9", CellValue = new CellValue("SBD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "C9", CellValue = new CellValue("Số CCCD"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "D9", CellValue = new CellValue("Họ và tên"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F9", CellValue = new CellValue("Ngày sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "G9", CellValue = new CellValue("Giới tính"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "H9", CellValue = new CellValue("Nơi sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "I9", CellValue = new CellValue("Lý thuyết"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "J9", CellValue = new CellValue("Thực hành"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "K9", CellValue = new CellValue("Kết quả"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "L9", CellValue = new CellValue("Lớp"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);


                int tt = 1;
                UInt32 hang = 10;
                var dsThisinh = list.OrderBy(m => m.SoBD).ToList();
                foreach (var ts in dsThisinh)
                {
                    firstRow = new Row();
                    firstRow.RowIndex = hang;

                    dataCell = new Cell() { CellReference = "A" + hang.ToString(), CellValue = new CellValue((decimal)(hang - 9)), DataType = new EnumValue<CellValues>(CellValues.Number) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "B" + hang.ToString(), CellValue = new CellValue(ts.SoBD), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "C" + hang.ToString(), CellValue = new CellValue(ts.CCCD), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "D" + hang.ToString(), CellValue = new CellValue(ts.HovaDem), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "E" + hang.ToString(), CellValue = new CellValue(ts.Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "F" + hang.ToString(), CellValue = new CellValue(ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    string gt = ts.GioiTinh != null && ts.GioiTinh == 0 ? "Nữ" : "Nam";
                    dataCell = new Cell() { CellReference = "G" + hang.ToString(), CellValue = new CellValue(gt), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    dataCell = new Cell() { CellReference = "H" + hang.ToString(), CellValue = new CellValue(ts.NoiSinh_Tinh_Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    if (ts.DiemLT != null)
                    {
                        dataCell = new Cell() { CellReference = "I" + hang.ToString(), CellValue = new CellValue(ts.DiemLT.Value), DataType = new EnumValue<CellValues>(CellValues.Number) };
                        firstRow.AppendChild(dataCell);
                    }
                    if (ts.DiemTH != null)
                    {
                        dataCell = new Cell() { CellReference = "J" + hang.ToString(), CellValue = new CellValue(ts.DiemTH.Value), DataType = new EnumValue<CellValues>(CellValues.Number) };
                        firstRow.AppendChild(dataCell);
                    }

                    dataCell = new Cell() { CellReference = "K" + hang.ToString(), CellValue = new CellValue(ts.Ketqua), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    dataCell = new Cell() { CellReference = "L" + hang.ToString(), CellValue = new CellValue(ts.LopID), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);


                    hang = hang + 1;
                    sheetData.AppendChild(firstRow);
                }
                firstRow = new Row();
                firstRow.RowIndex = hang;
                string s = "Danh sách gồm có " + dsThisinh.Count().ToString() + " thí sinh";
                dataCell = new Cell() { CellReference = "A" + hang.ToString(), CellValue = new CellValue(s), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                MergeCells mergeCells = new MergeCells();
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A1:E1") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("F1:K1") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A2:E2") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("F2:K2") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("F3:K3") });

                mergeCells.Append(new MergeCell() { Reference = new StringValue("A5:K5") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A6:K6") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A7:K7") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A8:K8") });
                worksheetPart.Worksheet.InsertAfter(mergeCells, worksheetPart.Worksheet.Elements<SheetData>().First());

                workbookPart.Workbook.Save();

            }

            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        /// <summary>
        /// Export danh sách cấp chứng chỉ
        /// </summary>
        /// <param name="list"></param>
        /// <returns></returns>
        public FileStreamResult DScapCCToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "Danh sách cấp chứng chỉ";
            var stream = new MemoryStream();
            //var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());

                var headerRow = new Row();

                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("STT"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("SBD"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Họ và đệm"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Tên"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Ngày sinh"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Nơi sinh"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Giới tính"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Dân tộc"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Lý thuyết"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Thực hành"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Số hiệu Chứng chỉ"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Số vào sổ"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });

                sheetData.AppendChild(headerRow);

                int tt = 1;
                var dsThisinh = list.OrderBy(m => m.SoBD).ToList();
                foreach (var ts in dsThisinh)
                {
                    var row = new Row();
                    var cell = new Cell();
                    cell.CellValue = new CellValue(tt);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.SoBD);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.HovaDem);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.Ten);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.NgaySinh);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.NoiSinh_Tinh_Ten);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    
                    if (ts.GioiTinh == 1)
                    {
                        cell.CellValue = new CellValue("Nam");
                    }
                    else
                    {
                        cell.CellValue = new CellValue("Nữ");
                    }
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.DanToc_Ten);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.DataType = CellValues.Number;
                    cell.CellValue = new CellValue(ts.DiemLT.Value);                    
                    row.Append(cell);

                    cell = new Cell();
                    cell.DataType = CellValues.Number;
                    cell.CellValue = new CellValue(ts.DiemTH.Value);
                    

                    row.Append(cell);

                    tt = tt + 1;
                    sheetData.AppendChild(row);
                }


                workbookPart.Workbook.Save();

            }
            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }

        //
        /// <summary>
        /// Export danh sách cấp chứng chỉ
        /// </summary>
        /// <param name="list"></param>
        /// <returns></returns>
        public FileStreamResult Tinhoc03SoCapChungchiToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "Sổ cấp cấp chứng chỉ";
            var stream = new MemoryStream();
            //var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());

                var headerRow = new Row();
                // Header
                //add a row
                Row firstRow = new Row();
                firstRow.RowIndex = (UInt32)1;
                //create a cell in C1 (the upper left most cell of the merged cells)
                Cell dataCell = new Cell() { CellReference = "A1", CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);                
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)2;
                dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("TRUNG TÂM NGOẠI NGỮ - TIN HỌC"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)3;
                dataCell = new Cell() { CellReference = "A3", CellValue = new CellValue("SỔ GỐC CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);                
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)4;
                dataCell = new Cell() { CellReference = "A4", CellValue = new CellValue("Hội đồng thi chứng chỉ Ứng dụng Công nghệ Thông tin cơ bản"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)5;
                dataCell = new Cell() { CellReference = "A5", CellValue = new CellValue("Đợt .... năm .... từ ngày ... tháng .... năm ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)7;
                dataCell = new Cell() { CellReference = "A7", CellValue = new CellValue("STT"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);                
                dataCell = new Cell() { CellReference = "B7", CellValue = new CellValue("Họ và tên"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "C7", CellValue = new CellValue("Ngày sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "D7", CellValue = new CellValue("Nơi sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "E7", CellValue = new CellValue("Giới tính"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "F7", CellValue = new CellValue("Dân tộc"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "G7", CellValue = new CellValue("Điểm thi"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);


                dataCell = new Cell() { CellReference = "I7", CellValue = new CellValue("Số hiệu chứng chỉ"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "J7", CellValue = new CellValue("Số vào sổ gốc cấp chứng chỉ"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "K7", CellValue = new CellValue("Người nhận chứng chỉ ký và ghi rõ họ tên"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "L7", CellValue = new CellValue("Ghi chú"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = (UInt32)8;
                dataCell = new Cell() { CellReference = "G8", CellValue = new CellValue("Lý thuyết"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                dataCell = new Cell() { CellReference = "H8", CellValue = new CellValue("Thực hành"), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);

                int tt = 1;
                UInt32 hang = 9;
                var dsThisinh = list.OrderBy(m => m.SoBD).ToList();
                foreach (var ts in dsThisinh)
                {
                    firstRow = new Row();
                    firstRow.RowIndex = hang;

                    dataCell = new Cell() { CellReference = "A" + hang.ToString(), CellValue = new CellValue((decimal)(hang - 8)), DataType = new EnumValue<CellValues>(CellValues.Number) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "B" + hang.ToString(), CellValue = new CellValue(ts.HovaDem + " " + ts.Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "C" + hang.ToString(), CellValue = new CellValue(ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    dataCell = new Cell() { CellReference = "D" + hang.ToString(), CellValue = new CellValue(ts.NoiSinh_Tinh_Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    string gt = ts.GioiTinh != null && ts.GioiTinh == 0 ? "Nữ" : "Nam";
                    dataCell = new Cell() { CellReference = "E" + hang.ToString(), CellValue = new CellValue(gt), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    dataCell = new Cell() { CellReference = "F" + hang.ToString(), CellValue = new CellValue(ts.DanToc_Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);

                    if (ts.DiemLT != null)
                    {
                        dataCell = new Cell() { CellReference = "G" + hang.ToString(), CellValue = new CellValue(ts.DiemLT.Value), DataType = new EnumValue<CellValues>(CellValues.Number) };
                        firstRow.AppendChild(dataCell);
                    }
                    if (ts.DiemTH != null)
                    {
                        dataCell = new Cell() { CellReference = "H" + hang.ToString(), CellValue = new CellValue(ts.DiemTH.Value), DataType = new EnumValue<CellValues>(CellValues.Number) };
                        firstRow.AppendChild(dataCell);
                    }

                    dataCell = new Cell() { CellReference = "I" + hang.ToString(), CellValue = new CellValue(ts.SoChungChi), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    
                    dataCell = new Cell() { CellReference = "J" + hang.ToString(), CellValue = new CellValue(ts.SoVaoSo), DataType = new EnumValue<CellValues>(CellValues.String) };
                    firstRow.AppendChild(dataCell);
                    
                    hang = hang + 1;
                    sheetData.AppendChild(firstRow);
                }
                firstRow = new Row();
                firstRow.RowIndex = hang;
                string s = "Hà Nội, ngày .... tháng .... năm ....";
                dataCell = new Cell() { CellReference = "G" + hang.ToString(), CellValue = new CellValue(s), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                firstRow = new Row();
                firstRow.RowIndex = hang+1;
                s = "GIÁM ĐỐC TRUNG TÂM NGOẠI NGỮ TIN HỌC";
                dataCell = new Cell() { CellReference = "G" + (hang+1).ToString(), CellValue = new CellValue(s), DataType = new EnumValue<CellValues>(CellValues.String) };
                firstRow.AppendChild(dataCell);
                sheetData.AppendChild(firstRow);

                MergeCells mergeCells = new MergeCells();
                mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + hang.ToString() + ":L" + hang.ToString()) });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("G" + (hang+1).ToString() + ":L" + (hang+1).ToString()) });


                mergeCells.Append(new MergeCell() { Reference = new StringValue("A1:E1") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A2:E2") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A3:L3") });

                mergeCells.Append(new MergeCell() { Reference = new StringValue("A4:L4") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("A5:L5") });

                mergeCells.Append(new MergeCell() { Reference = new StringValue("A7:A8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("B7:B8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("C7:C8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("D7:D8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("E7:E8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("F7:F8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("G7:H7") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("I7:I8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("J7:J8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("K7:K8") });
                mergeCells.Append(new MergeCell() { Reference = new StringValue("L7:L8") });

                SetBorderAndFill(workbookPart, worksheetPart, "A1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                SetBorderAndFill(workbookPart, worksheetPart, "A2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                SetBorderAndFill(workbookPart, worksheetPart, "A3", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                SetBorderAndFill(workbookPart, worksheetPart, "A7", false, true, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                SetBorderAndFill(workbookPart, worksheetPart, "B7", false, true, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                SetBorderAndFill(workbookPart, worksheetPart, "C7", false, true, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                SetBorderAndFill(workbookPart, worksheetPart, "D7", false, true, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                //SetBorderAndFill(workbookPart, worksheetPart, "A7:L"+hang.ToString(), false, true, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                for(char col ='A'; col <= 'L'; col++)
                {
                    for (uint h=9; h<hang; h++)
                    {
                        SetBorderAndFill(workbookPart, worksheetPart, col + h.ToString(), false, true, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                    }
                }
                worksheetPart.Worksheet.InsertAfter(mergeCells, worksheetPart.Worksheet.Elements<SheetData>().First());

                workbookPart.Workbook.Save();

            }

            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }

        public FileStreamResult DSAnhToExcel(List<DangkyTH03_View> list)
        {   
            string fileName = "danh sách ảnh phòng thi";
            var stream = new MemoryStream();
            var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                foreach (var pt in dsPhongthi)
                {
                    var dsCathi = list.Where(m => m.PhongThi == pt.PhongThi).DistinctBy(m => m.CaThi).ToList();
                    foreach (var c in dsCathi)
                    {
                        ///
                        var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                        worksheetPart.Worksheet = new Worksheet();
                        var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = pt.PhongThi + "_" + c.CaThi };
                        _sheetId++;
                        sheets.Append(sheet);

                        //workbookPart.Workbook.Save();

                        var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());
                        ///                                             

                        //add a row
                        Row firstRow = new Row();
                        firstRow.RowIndex = (UInt32)1;
                        //create a cell in C1 (the upper left most cell of the merged cells)
                        Cell dataCell = new Cell() { CellReference = "A1", CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "C1", CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)2;
                        dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "C2", CellValue = new CellValue("Độc lập - Tự do - Hạnh phúc"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)3;
                        //dataCell = new Cell() { CellReference = "A2", CellValue = new CellValue("HĐ THI CHỨNG CHỈ ƯDCNTT CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        //firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "C3", CellValue = new CellValue("..., ngày  tháng ... năm ...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)5;
                        dataCell = new Cell() { CellReference = "A5", CellValue = new CellValue("DANH SÁCH PHÒNG THI"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)6;
                        dataCell = new Cell() { CellReference = "A6", CellValue = new CellValue("KỲ THI CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN CƠ BẢN"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = (UInt32)7;
                        dataCell = new Cell() { CellReference = "A7", CellValue = new CellValue("Đợt thi...."), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        //sheetData.AppendChild(firstRow);

                        //firstRow = new Row();
                        //firstRow.RowIndex = (UInt32)8;

                        dataCell = new Cell() { CellReference = "B7", CellValue = new CellValue("Phòng thi:" + pt.PhongThi), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        dataCell = new Cell() { CellReference = "C7", CellValue = new CellValue("Ngày thi: "), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        //sheetData.AppendChild(firstRow);

                        //firstRow = new Row();
                        //firstRow.RowIndex = (UInt32)9;
                        dataCell = new Cell() { CellReference = "D7", CellValue = new CellValue("Ca thi: " + c.CaThi + " Thời gian thi:"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        UInt32 hang = 8;
                        UInt32 startData = 8;
                        var dsThisinh = list.Where(m => m.PhongThi == pt.PhongThi).Where(m => m.CaThi == c.CaThi).ToList();
                        List<string> cot = new List<string>() { "A", "B", "C", "D", "E" };
                        int cotIndex = 0;
                        firstRow = new Row();
                        
                        Row Row1 = new Row();
                        Row Row2 = new Row();
                        Row Row3 = new Row();

                        Row1.RowIndex = hang;
                        Row2.RowIndex = hang+1;
                        Row3.RowIndex = hang+2;


                        foreach (var ts in dsThisinh)
                        {
                            dataCell = new Cell() { CellReference = cot[cotIndex] + hang.ToString(), CellValue = new CellValue(ts.HovaDem + " " + ts.Ten) , DataType = new EnumValue<CellValues>(CellValues.String) };
                            Row1.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = cot[cotIndex] + (hang+1).ToString(), CellValue = new CellValue( ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                            Row2.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = cot[cotIndex] + (hang + 2).ToString(), CellValue = new CellValue(ts.SoBD), DataType = new EnumValue<CellValues>(CellValues.String) };
                            Row3.AppendChild(dataCell);

                            
                            if (cotIndex >0 && cotIndex % 3 == 0)
                            {
                                hang = hang + 4;
                                cotIndex = 0;
                                sheetData.AppendChild(Row1);
                                sheetData.AppendChild(Row2);
                                sheetData.AppendChild(Row3);

                                Row1 = new Row();
                                Row2 = new Row();
                                Row3 = new Row();

                                Row1.RowIndex = hang;
                                Row2.RowIndex = hang + 1;
                                Row3.RowIndex = hang + 2;
                            }else
                            {
                                cotIndex = cotIndex + 1;
                            }
                                        

                        }

                        UInt32 ft1 = hang;
                        UInt32 ft2 = hang + 1;
                        UInt32 ft3 = hang + 2;

                        firstRow = new Row();
                        firstRow.RowIndex = ft1;
                        dataCell = new Cell() { CellReference = "A" + ft1.ToString(), CellValue = new CellValue("Tổng số: "+ dsThisinh.Count +" thí sinh"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);

                        firstRow = new Row();
                        firstRow.RowIndex = ft2;
                        
                        dataCell = new Cell() { CellReference = "C" + ft2.ToString(), CellValue = new CellValue("CHỦ TỊCH HỘI ĐỒNG THI"), DataType = new EnumValue<CellValues>(CellValues.String) };
                        firstRow.AppendChild(dataCell);
                        sheetData.AppendChild(firstRow);


                        ////create a MergeCells class to hold each MergeCell
                        MergeCells mergeCells = new MergeCells();

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A1:B1") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("C1:E1") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A2:B2") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("C2:E2") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("C3:E3") });

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A5:E5") });
                        mergeCells.Append(new MergeCell() { Reference = new StringValue("A6:E6") });
                        

                        mergeCells.Append(new MergeCell() { Reference = new StringValue("C" + ft2.ToString() +":E" + ft2.ToString()) });

                        SetBorderAndFill(workbookPart, worksheetPart, "A1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "C1", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        SetBorderAndFill(workbookPart, worksheetPart, "A2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "C2", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "C3", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        SetBorderAndFill(workbookPart, worksheetPart, "A5", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        SetBorderAndFill(workbookPart, worksheetPart, "A6", false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);

                        SetBorderAndFill(workbookPart, worksheetPart, "C" + ft2.ToString(), false, false, HorizontalAlignmentValues.Center, VerticalAlignmentValues.Center);
                        
                        worksheetPart.Worksheet.InsertAfter(mergeCells, worksheetPart.Worksheet.Elements<SheetData>().First());
                    }
                }
                workbookPart.Workbook.Save();
            }


            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //
        public FileStreamResult DSTKPhongthiToExcel(List<DangkyTH03_View> list)
        {
            string fileName = "dsTKThi";
            var stream = new MemoryStream();
            var dsPhongthi = list.DistinctBy(m => m.PhongThi).ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                foreach (var pt in dsPhongthi)
                {
                    var dsCathi = list.Where(m => m.PhongThi == pt.PhongThi).DistinctBy(m => m.CaThi).ToList();
                    foreach (var c in dsCathi)
                    {
                        ///
                        var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                        worksheetPart.Worksheet = new Worksheet();
                        var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = pt.PhongThi + "_" + c.CaThi };
                        _sheetId++;
                        sheets.Append(sheet);

                        //workbookPart.Workbook.Save();

                        var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());
                        ///                                             

                        //add a row
                        Row firstRow = new Row();
                        firstRow.RowIndex = (UInt32)1;
                        //create a cell in C1 (the upper left most cell of the merged cells)
                        Cell dataCell = new Cell();

                        UInt32 hang = 1;
                        UInt32 startData = 8;
                        var dsThisinh = list.Where(m => m.PhongThi == pt.PhongThi).Where(m => m.CaThi == c.CaThi).ToList();
                        List<string> cot = new List<string>() { "A", "B", "C", "D", "E" };
                        int cotIndex = 0;
                        firstRow = new Row();

                        Row Row1 = new Row();
                        Row Row2 = new Row();
                        Row Row3 = new Row();
                        Row Row4 = new Row();

                        Row1.RowIndex = hang;
                        Row2.RowIndex = hang + 1;
                        Row3.RowIndex = hang + 2;


                        foreach (var ts in dsThisinh)
                        {
                            dataCell = new Cell() { CellReference = cot[cotIndex] + hang.ToString(), CellValue = new CellValue("Họ và tên:"+ts.HovaDem + " " + ts.Ten), DataType = new EnumValue<CellValues>(CellValues.String) };
                            Row1.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = cot[cotIndex] + (hang + 1).ToString(), CellValue = new CellValue("Ngày sinh:" + ts.NgaySinh), DataType = new EnumValue<CellValues>(CellValues.String) };
                            Row2.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = cot[cotIndex] + (hang + 2).ToString(), CellValue = new CellValue("Tài khoản:" + ts.SoBD), DataType = new EnumValue<CellValues>(CellValues.String) };
                            Row3.AppendChild(dataCell);
                            dataCell = new Cell() { CellReference = cot[cotIndex] + (hang + 3).ToString(), CellValue = new CellValue("Mật khẩu:" + ts.Matkhau), DataType = new EnumValue<CellValues>(CellValues.String) };
                            Row4.AppendChild(dataCell);

                            if (cotIndex > 0 && cotIndex % 3 == 0)
                            {
                                hang = hang + 5;
                                cotIndex = 0;
                                sheetData.AppendChild(Row1);
                                sheetData.AppendChild(Row2);
                                sheetData.AppendChild(Row3);
                                sheetData.AppendChild(Row4);

                                Row1 = new Row();
                                Row2 = new Row();
                                Row3 = new Row();
                                Row4 = new Row();

                                Row1.RowIndex = hang;
                                Row2.RowIndex = hang + 1;
                                Row3.RowIndex = hang + 2;
                                Row4.RowIndex = hang + 3;
                            }
                            else
                            {
                                cotIndex = cotIndex + 1;
                            }
                            
                        }                       
                        
                    }
                }
                workbookPart.Workbook.Save();
            }


            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //
        public FileStreamResult Taichinh_DutruKP(List<TAICHINH_DuTruKP> list)
        {
            string fileName = "Dự trù kinh phí";
            var stream = new MemoryStream();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());
                //Hàng đơn vị ban hành văn bản
                var headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());// cột trống
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);
                //HÀNG 2
                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("ĐƠN VỊ"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());// cột trống
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Độc lập - Tự do - Hạnh phuc"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);
                
                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);

                //HÀNG 3
                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("DỰ TRÙ KINH PHÍ NĂM 2025"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                
                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);
                //

                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("STT"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Nội dung"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Diễn giải"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Số tiền"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Ghi chú"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });               


                sheetData.AppendChild(headerRow);

                int tt = 1;
                //var dsThisinh = list.OrderBy(m => m.SoBD).ToList();
                long sum = 0;
                foreach (var ts in list)
                {
                    var row = new Row();
                    var cell = new Cell();
                    cell.CellValue = new CellValue(tt);
                    cell.DataType = CellValues.Number;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.TenMucChi);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue(ts.DienGiai);
                    cell.DataType = CellValues.String;
                    row.Append(cell);

                    cell = new Cell();
                    cell.CellValue = new CellValue((double)ts.SoTien);
                    cell.DataType = CellValues.Number;
                    row.Append(cell);
                    

                    cell = new Cell();
                    //cell.CellValue = new CellValue(ts.SoTien);
                    cell.DataType = CellValues.Number;
                    row.Append(cell);
                    sum = sum + ts.SoTien;

                    tt = tt + 1;
                    sheetData.AppendChild(row);
                }
                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("TỔNG"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue((double)sum),
                    DataType = new EnumValue<CellValues>(CellValues.Number)
                });

                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);

                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Hà Nội, ngày " + DateTime.Now.Day + " tháng " + DateTime.Now.Month + " năm " + DateTime.Now.Year),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);

                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("LÃNH ĐẠO ĐƠN VỊ"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);


                workbookPart.Workbook.Save();

            }
            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //      
        public FileStreamResult Taichinh_TongHopDutruKP(List<Khoa> donviList, List<TAICHINH_DuTruKP> list)
        {
            string fileName = "Tổng hợp dự trù kinh phí";
            var stream = new MemoryStream();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());
                //Hàng đơn vị ban hành văn bản
                var headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("TRUNG ƯƠNG ĐOÀN TNCS HỒ CHÍ MINH"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());// cột trống
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);
                //HÀNG 2
                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());// cột trống
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Độc lập - Tự do - Hạnh phuc"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);

                //HÀNG 3
                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("TỔNG HỢP DỰ TRÙ KINH PHÍ NĂM " + (DateTime.Now.Year+1)),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });

                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);
                //

                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("STT"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Đơn vị"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Nội dung"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Diễn giải"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Số tiền"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Ghi chú"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });


                sheetData.AppendChild(headerRow);
                
                UInt32 hang = 7;
                long sum_all_dv = 0;
                int tt = 1;
                foreach (var donvi in donviList)
                {
                    var ls = list.Where(x => x.MaDonVi.Equals(donvi.Id)).OrderBy(m=>m.MaMucChi).ToList();
                    if (ls ==null || ls.Count == 0)
                    {
                        continue;
                    }
                    //int tt = 1;
                    //var dsThisinh = list.OrderBy(m => m.SoBD).ToList();
                    long sum = 0;
                    bool first_row_of_each_dv = true;
                    foreach (var ts in ls)
                    {
                        var row= new Row();
                        var dataCell = new Cell();
                        row.RowIndex = hang;
                        if (first_row_of_each_dv)
                        {
                            first_row_of_each_dv = false;
                            dataCell = new Cell()
                            {
                                CellReference = "A" + hang.ToString(),
                                CellValue = new CellValue(tt),
                                DataType = new EnumValue<CellValues>(CellValues.Number)
                            };
                            row.AppendChild(dataCell);
                            
                            dataCell = new Cell()
                            {
                                CellReference = "B" + hang.ToString(),
                                CellValue = new CellValue(donvi.Name),
                                DataType = new EnumValue<CellValues>(CellValues.String)
                            };
                            row.AppendChild(dataCell);
                        }
                        dataCell = new Cell() { 
                            CellReference = "C" + hang.ToString(), 
                            CellValue = new CellValue(ts.TenMucChi), 
                            DataType = new EnumValue<CellValues>(CellValues.String) 
                        };
                        row.AppendChild(dataCell);

                        dataCell = new Cell()
                        {
                            CellReference = "D" + hang.ToString(),
                            CellValue = new CellValue(ts.DienGiai),
                            DataType = new EnumValue<CellValues>(CellValues.String)
                        };
                        row.AppendChild(dataCell);

                        dataCell = new Cell()
                        {
                            CellReference = "E" + hang.ToString(),
                            CellValue = new CellValue((double)ts.SoTien),
                            DataType = new EnumValue<CellValues>(CellValues.Number)
                        };
                        row.AppendChild(dataCell);

                        sum = sum + ts.SoTien;
                        
                        sheetData.AppendChild(row);

                        
                        hang = hang + 1;
                        
                    }
                    var footer_donvi = new Row();
                    var ftCell = new Cell()
                    {
                        CellReference = "C" + hang.ToString(),
                        CellValue = new CellValue(donvi.Name),
                        DataType = new EnumValue<CellValues>(CellValues.String)
                    };
                    footer_donvi.AppendChild(ftCell);
                    ftCell = new Cell()
                    {
                        CellReference = "E" + hang.ToString(),
                        CellValue = new CellValue((double)sum),
                        DataType = new EnumValue<CellValues>(CellValues.Number)
                    };
                    footer_donvi.AppendChild(ftCell);
                    sheetData.AppendChild(footer_donvi);
                    sum_all_dv += sum;
                    hang = hang + 1;
                    tt = tt + 1;
                }

                
                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("TỔNG"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue((double)sum_all_dv),
                    DataType = new EnumValue<CellValues>(CellValues.Number)
                });

                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);

                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Hà Nội, ngày " + DateTime.Now.Day + " tháng " + DateTime.Now.Month + " năm " + DateTime.Now.Year),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);

                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("LÃNH ĐẠO ĐƠN VỊ"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);


                workbookPart.Workbook.Save();

            }
            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //
        public FileStreamResult Taichinh_TongHopTheoMucChi(List<TAICHINH_MucChi> mucchiList, List<TAICHINH_DuTruKP> list)
        {
            string fileName = "Tổng hợp dự trù kinh phí theo mục chi";
            var stream = new MemoryStream();
            var tenMucChi = list.OrderBy(m=>m.TenMucChi).Select(m => m.TenMucChi).Distinct().ToList();

            using (var document = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
            {
                var workbookPart = document.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();

                var workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                GenerateWorkbookStylesPartContent(workbookStylesPart);
                var sheets = workbookPart.Workbook.AppendChild(new Sheets());
                UInt32 _sheetId = 1;
                var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                worksheetPart.Worksheet = new Worksheet();
                var sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = _sheetId, Name = "Sheet1" };
                _sheetId++;
                sheets.Append(sheet);

                var sheetData = worksheetPart.Worksheet.AppendChild(new SheetData());
                //Hàng đơn vị ban hành văn bản
                var headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("TRUNG ƯƠNG ĐOÀN TNCS HỒ CHÍ MINH"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());// cột trống
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);
                //HÀNG 2
                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("HỌC VIỆN THANH THIẾU NIÊN VIỆT NAM"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell());// cột trống
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Độc lập - Tự do - Hạnh phuc"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);

                //HÀNG 3
                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("TỔNG HỢP DỰ TRÙ KINH PHÍ NĂM " + (DateTime.Now.Year + 1)),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });

                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);
                //

                headerRow = new Row();
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("STT"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Nội dung"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Số tiền"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Ghi chú"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });


                sheetData.AppendChild(headerRow);

                UInt32 hang = 7;
                long sum_all_dv = 0;
                int tt = 1;
                foreach (var mucchi in tenMucChi)
                {
                    //var tongtien = list.Where(x => x.MaMucChi.Equals(mucchi.Id)).Sum(item =>item.SoTien);
                    var tongtien = list.Where(x => x.TenMucChi.Equals(mucchi)).Sum(item => item.SoTien);
                    var row = new Row();
                    var dataCell = new Cell();
                    row.RowIndex = hang;
                    dataCell = new Cell()
                    {
                        CellReference = "A" + hang.ToString(),
                        CellValue = new CellValue(tt),
                        DataType = new EnumValue<CellValues>(CellValues.Number)
                    };
                    row.AppendChild(dataCell);

                    dataCell = new Cell()
                    {
                        CellReference = "B" + hang.ToString(),
                        CellValue = new CellValue(mucchi),
                        DataType = new EnumValue<CellValues>(CellValues.String)
                    };
                    row.AppendChild(dataCell);
                    

                    dataCell = new Cell()
                    {
                        CellReference = "C" + hang.ToString(),
                        CellValue = new CellValue((double)tongtien),
                        DataType = new EnumValue<CellValues>(CellValues.Number)
                    };
                    row.AppendChild(dataCell);
                    sheetData.AppendChild(row);
                    sum_all_dv += tongtien;
                    hang = hang + 1;
                    tt = tt + 1;
                }


                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("TỔNG"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue((double)sum_all_dv),
                    DataType = new EnumValue<CellValues>(CellValues.Number)
                });

                sheetData.AppendChild(headerRow);

                // thêm hàng trống
                headerRow = new Row();
                sheetData.AppendChild(headerRow);

                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());
                
                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("Hà Nội, ngày " + DateTime.Now.Day + " tháng " + DateTime.Now.Month + " năm " + DateTime.Now.Year),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);

                //HÀNG tổng
                headerRow = new Row();
                headerRow.Append(new Cell());
                headerRow.Append(new Cell());

                headerRow.Append(new Cell()
                {
                    CellValue = new CellValue("LÃNH ĐẠO ĐƠN VỊ"),
                    DataType = new EnumValue<CellValues>(CellValues.String)
                });
                sheetData.AppendChild(headerRow);


                workbookPart.Workbook.Save();

            }
            if (stream?.Length > 0)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            var result = new FileStreamResult(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            result.FileDownloadName = (!string.IsNullOrEmpty(fileName) ? fileName : "Export") + ".xlsx";

            return result;
        }
        //
        public static object GetValue(object target, string name)
        {
            return target.GetType().GetProperty(name).GetValue(target);
        }

        public static IEnumerable<KeyValuePair<string, Type>> GetProperties(Type type)
        {
            return type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                    .Where(p => p.CanRead && IsSimpleType(p.PropertyType)).Select(p => new KeyValuePair<string, Type>(p.Name, p.PropertyType));
        }

        public static bool IsSimpleType(Type type)
        {
            var underlyingType = type.IsGenericType &&
                type.GetGenericTypeDefinition() == typeof(Nullable<>) ?
                Nullable.GetUnderlyingType(type) : type;

            var typeCode = Type.GetTypeCode(underlyingType);

            switch (typeCode)
            {
                case TypeCode.Boolean:
                case TypeCode.Byte:
                case TypeCode.Char:
                case TypeCode.DateTime:
                case TypeCode.Decimal:
                case TypeCode.Double:
                case TypeCode.Int16:
                case TypeCode.Int32:
                case TypeCode.Int64:
                case TypeCode.SByte:
                case TypeCode.Single:
                case TypeCode.String:
                case TypeCode.UInt16:
                case TypeCode.UInt32:
                case TypeCode.UInt64:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsNumeric(TypeCode typeCode)
        {
            switch (typeCode)
            {
                case TypeCode.Decimal:
                case TypeCode.Double:
                case TypeCode.Int16:
                case TypeCode.Int32:
                case TypeCode.Int64:
                case TypeCode.UInt16:
                case TypeCode.UInt32:
                case TypeCode.UInt64:
                    return true;
                default:
                    return false;
            }
        }

        private static void GenerateWorkbookStylesPartContent(WorkbookStylesPart workbookStylesPart1)
        {
            Stylesheet stylesheet1 = new Stylesheet() { MCAttributes = new MarkupCompatibilityAttributes() { Ignorable = "x14ac x16r2 xr" } };
            stylesheet1.AddNamespaceDeclaration("mc", "http://schemas.openxmlformats.org/markup-compatibility/2006");
            stylesheet1.AddNamespaceDeclaration("x14ac", "http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac");
            stylesheet1.AddNamespaceDeclaration("x16r2", "http://schemas.microsoft.com/office/spreadsheetml/2015/02/main");
            stylesheet1.AddNamespaceDeclaration("xr", "http://schemas.microsoft.com/office/spreadsheetml/2014/revision");

            Fonts fonts1 = new Fonts() { Count = (UInt32Value)1U, KnownFonts = true };

            Font font1 = new Font();
            FontSize fontSize1 = new FontSize() { Val = 12D };
            Color color1 = new Color() { Theme = (UInt32Value)1U };
            FontName fontName1 = new FontName() { Val = "Times New Roman" };
            FontFamilyNumbering fontFamilyNumbering1 = new FontFamilyNumbering() { Val = 2 };
            FontScheme fontScheme1 = new FontScheme() { Val = FontSchemeValues.Minor };

            font1.Append(fontSize1);
            font1.Append(color1);
            font1.Append(fontName1);
            font1.Append(fontFamilyNumbering1);
            font1.Append(fontScheme1);

            fonts1.Append(font1);

            Fills fills1 = new Fills() { Count = (UInt32Value)2U };

            Fill fill1 = new Fill();
            PatternFill patternFill1 = new PatternFill() { PatternType = PatternValues.None };

            fill1.Append(patternFill1);

            Fill fill2 = new Fill();
            PatternFill patternFill2 = new PatternFill() { PatternType = PatternValues.Gray125 };

            fill2.Append(patternFill2);

            fills1.Append(fill1);
            fills1.Append(fill2);

            Borders borders1 = new Borders() { Count = (UInt32Value)1U };

            Border border1 = new Border();
            LeftBorder leftBorder1 = new LeftBorder();
            RightBorder rightBorder1 = new RightBorder();
            TopBorder topBorder1 = new TopBorder();
            BottomBorder bottomBorder1 = new BottomBorder();
            DiagonalBorder diagonalBorder1 = new DiagonalBorder();

            border1.Append(leftBorder1);
            border1.Append(rightBorder1);
            border1.Append(topBorder1);
            border1.Append(bottomBorder1);
            border1.Append(diagonalBorder1);

            borders1.Append(border1);

            CellStyleFormats cellStyleFormats1 = new CellStyleFormats() { Count = (UInt32Value)1U };
            CellFormat cellFormat1 = new CellFormat() { NumberFormatId = (UInt32Value)0U, FontId = (UInt32Value)0U, FillId = (UInt32Value)0U, BorderId = (UInt32Value)0U };

            cellStyleFormats1.Append(cellFormat1);

            CellFormats cellFormats1 = new CellFormats() { Count = (UInt32Value)2U };
            CellFormat cellFormat2 = new CellFormat() { NumberFormatId = (UInt32Value)0U, FontId = (UInt32Value)0U, FillId = (UInt32Value)0U, BorderId = (UInt32Value)0U, FormatId = (UInt32Value)0U };
            CellFormat cellFormat3 = new CellFormat() { NumberFormatId = (UInt32Value)14U, FontId = (UInt32Value)0U, FillId = (UInt32Value)0U, BorderId = (UInt32Value)0U, FormatId = (UInt32Value)0U, ApplyNumberFormat = true };

            cellFormats1.Append(cellFormat2);
            cellFormats1.Append(cellFormat3);

            CellStyles cellStyles1 = new CellStyles() { Count = (UInt32Value)1U };
            CellStyle cellStyle1 = new CellStyle() { Name = "Normal", FormatId = (UInt32Value)0U, BuiltinId = (UInt32Value)0U };

            cellStyles1.Append(cellStyle1);
            DifferentialFormats differentialFormats1 = new DifferentialFormats() { Count = (UInt32Value)0U };
            TableStyles tableStyles1 = new TableStyles() { Count = (UInt32Value)0U, DefaultTableStyle = "TableStyleMedium2", DefaultPivotStyle = "PivotStyleLight16" };

            StylesheetExtensionList stylesheetExtensionList1 = new StylesheetExtensionList();

            StylesheetExtension stylesheetExtension1 = new StylesheetExtension() { Uri = "{EB79DEF2-80B8-43e5-95BD-54CBDDF9020C}" };
            stylesheetExtension1.AddNamespaceDeclaration("x14", "http://schemas.microsoft.com/office/spreadsheetml/2009/9/main");

            StylesheetExtension stylesheetExtension2 = new StylesheetExtension() { Uri = "{9260A510-F301-46a8-8635-F512D64BE5F5}" };
            stylesheetExtension2.AddNamespaceDeclaration("x15", "http://schemas.microsoft.com/office/spreadsheetml/2010/11/main");

            OpenXmlUnknownElement openXmlUnknownElement4 = OpenXmlUnknownElement.CreateOpenXmlUnknownElement("<x15:timelineStyles defaultTimelineStyle=\"TimeSlicerStyleLight1\" xmlns:x15=\"http://schemas.microsoft.com/office/spreadsheetml/2010/11/main\" />");

            stylesheetExtension2.Append(openXmlUnknownElement4);

            stylesheetExtensionList1.Append(stylesheetExtension1);
            stylesheetExtensionList1.Append(stylesheetExtension2);

            stylesheet1.Append(fonts1);
            stylesheet1.Append(fills1);
            stylesheet1.Append(borders1);
            stylesheet1.Append(cellStyleFormats1);
            stylesheet1.Append(cellFormats1);
            stylesheet1.Append(cellStyles1);
            stylesheet1.Append(differentialFormats1);
            stylesheet1.Append(tableStyles1);
            stylesheet1.Append(stylesheetExtensionList1);

            workbookStylesPart1.Stylesheet = stylesheet1;
        }
    }
}
