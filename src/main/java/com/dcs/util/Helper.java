package com.dcs.util;


import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.google.common.io.Files;
import com.jwtutil.JWTUtil;

public class Helper {

    private static final String PROJECT_CONFIG_BUNDLE_NAME = "application";
    private static final String STRING_PARAM = "[param]";
    private static final String STRING_UTF8 = "UTF-8";
    private static final String DATE_FORMAT_SHORT = "dd/MM/yyyy";
    private static final String STRING_SERVERIP = "serverIP";
    private static final String[] IP_HEADER_CANDIDATES = {"X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP","HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP", "HTTP_CLIENT_IP",            "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_VIA", "REMOTE_ADDR"};
    private static final String SECRET_KEY_1 = "ssdkF$HUy2A#D%kd";
    private static final String SECRET_KEY_2 = "weJiSEvR5yAC5ftB";
    private static IvParameterSpec ivParameterSpec;
    private static SecretKeySpec secretKeySpec;
    private static Cipher cipher;


    private Helper() {
    }



    public static String date2String(Date date) {
        return date2String(date, DATE_FORMAT_SHORT);
    }

    public static String date2String(long date, String format) {
        return date2String(new Date(date), format);
    }

    public static String date2String(Date date, String format) {
        if (date != null) {
            SimpleDateFormat sdf = new SimpleDateFormat();
            sdf.applyPattern(format);
            return sdf.format(date);
        } else {
            return "";
        }
    }

    public static String getServerIPAddress() {
        String ipAddress = "";
        try {
            InetAddress ip;
            ip = InetAddress.getLocalHost();
            ipAddress = ip.getHostAddress();
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }

        return ipAddress;
    }

    public static void errorLogger(Class<?> className, Exception e) {
       /* ErrorHandler eh = new ErrorHandler(className, e);
        eh.setLogtype("error");
        eh.setServerName(getServerIPAddress());
        eh.logwrite();*/
    }

    public static void errorLogger(Class<?> className, Exception e, String extraInfo) {
        /*ErrorHandler eh = new ErrorHandler(className, e);
        eh.setLogtype("error");
        eh.setServerName(getServerIPAddress());
        eh.setExtraInfo(extraInfo);
        eh.logwrite();*/
    }

    public static String checkNulls(Object value, String newVal) {
        return checkNulls(value, newVal, true);
    }

    public static String checkNulls(Object value, String newVal, boolean isTrim) {
        try {
            if (value == null || "null".equals(value))
                return newVal;
            else {
                String str = String.valueOf(value);
                if (isTrim)
                    str = str.trim();

                if (str.length() < 1)
                    return newVal;
                else
                    return str;
            }
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return "";
    }

    public static Date dateAddYear(Date date, int year) {
        Date newdate = date;
        try {
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            cal.add(Calendar.YEAR, year);
            newdate = cal.getTime();

        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return newdate;
    }

    public static Date dateAddMonth(Date date, int month) {
        Date newdate = date;
        try {
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            cal.add(Calendar.MONTH, month);
            newdate = cal.getTime();

        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return newdate;
    }

    public static Date dateAdd(Date date, int day) {
        Date newdate = date;
        try {
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            cal.add(Calendar.DAY_OF_MONTH, day);
            newdate = cal.getTime();

        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return newdate;
    }

    public static Date string2Date(String strDate) {
        return string2Date(strDate, DATE_FORMAT_SHORT);
    }

    public static Date string2Date(String strDate, String format) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(format);
            return sdf.parse(strDate);
        } catch (Exception e) {
            if (format.indexOf("-") >= 3) {
                return string2Date(strDate, "DATE_FORMAT_YYYYMMDD");
            } else {
                Helper.errorLogger(Helper.class, e, " strDate..:" + strDate + " format..:" + format);
            }
        }
        return null;
    }

    public static double roundDecimal(double price) {
        DecimalFormat twoDigits = new DecimalFormat("0.0000", DecimalFormatSymbols.getInstance(new Locale("EN")));
        return BigDecimal.valueOf(Double.valueOf(twoDigits.format(price))).doubleValue();
    }

    public static double roundDouble(double input) {
        return Math.round(input * Math.pow(10, (double) 2.0)) / Math.pow(10, (double) 2.0);
    }

    public static double dateDifferent(Date pfrom, Date pto, int differentType) {

        Date from = pfrom;
        Date to = pto;

        if (from == null) {
            from = new Date();
        }
        if (to == null) {
            to = new Date();
        }

        Calendar calendar1 = Calendar.getInstance();
        Calendar calendar2 = Calendar.getInstance();
        calendar1.setTime(from);
        calendar2.setTime(to);
        long milliseconds1 = calendar1.getTimeInMillis();
        long milliseconds2 = calendar2.getTimeInMillis();
        double diff = milliseconds2 - milliseconds1;

        double left = 0;
        if (differentType == Calendar.SECOND) {
            left = diff / 1000L;
        } else if (differentType == Calendar.MINUTE) {
            left = diff / (60L * 1000L);
        } else if (differentType == Calendar.HOUR) {
            left = diff / (60L * 60L * 1000L);
        } else if (differentType == Calendar.DATE) {
            left = Helper.roundDecimal(diff / (24d * 60d * 60d * 1000d));
        } else if (differentType == Calendar.MILLISECOND) {
            left = diff;
        } else if (differentType == Calendar.YEAR) {
            left = Helper.roundDouble(diff / (365d * 24d * 60d * 60d * 1000d));
        }

        return left;
    }

    public static boolean isEmpty(String str) {
        if (str == null || str.trim().length() == 0)
            return true;
        else
            return false;
    }

    public static String generateMD5(String value) {
        StringBuilder sb = new StringBuilder();
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(value.getBytes(STRING_UTF8));

            byte byteData[] = md.digest();

            // convert the byte to hex format method 1
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
        } catch (RuntimeException | UnsupportedEncodingException | NoSuchAlgorithmException e) {
            Helper.errorLogger(Helper.class, e);
        }
        return sb.toString();
    }



    public static String removeForbiddenChar(String pstr) {
        return removeForbiddenChar(pstr, "");
    }

    public static String removeForbiddenChar(String pstr, String newStr) {
        String str = pstr;
        str = Helper.checkNulls(str, "");
        str = str.replace("\\", newStr);
        str = str.replace("\"", newStr);
        str = str.replace("'", newStr);
        str = str.replace("`", newStr);
        str = str.replace("]", newStr);
        str = str.replace("[", newStr);
        str = str.replace("*", newStr);
        str = str.replace(",", newStr);
        str = str.replace("?", newStr);
        str = str.replace("&", newStr);
        str = str.replace("!", newStr);
        str = str.replace("#", newStr);
        str = str.replace("~", newStr);
        str = str.replace("/", newStr);
        str = str.replace("(", newStr);
        str = str.replace(")", newStr);
        str = str.replace(" ", newStr);
        return str.trim();
    }

    public static java.sql.Date convert2SQLDate(Date date) {
        if (date != null)
            return new java.sql.Date(date.getTime());
        else
            return null;
    }

    public static String fileDeleteFromDisk(String path) {
        String result = "OK";
        boolean isDeleted = false;
        try {
            File file = new File(path);
            if (file.exists() && file.isFile()) {
                isDeleted = file.delete();
            }
            if (!isDeleted) {
                result = path + " silinemedi.";
            }
            return result;
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
            result = e.getMessage();
        }
        return result;
    }

    public static String fileWrite2Disk(String path, String fileName, File file) {
        String result = "OK";
        BufferedOutputStream stream = null;
        String newFilePath = "";
        boolean created = false;
        try {
            File dir = new File(path);
            if (!dir.exists()) {
                created = dir.mkdirs();
            }
            if (created) {
                String newFileName = removeForbiddenChar(fileName).toLowerCase(Locale.ENGLISH);
                newFilePath = path + "/" + newFileName;
                File newFile = new File(newFilePath);
                stream = new BufferedOutputStream(new FileOutputStream(newFile));
                stream.write(Files.toByteArray(file));
                stream.close();
            }
            return result;
        } catch (RuntimeException | IOException e) {
            Helper.errorLogger(Helper.class, e);
            result = e.getMessage();
        } finally {
            if (stream != null)
                try {
                    stream.close();
                } catch (IOException e) {
                    Helper.errorLogger(Helper.class, e);
                }
        }
        return result;
    }

    public static String readHtmlPage(String urlPath) {
        StringBuilder ticket = new StringBuilder();
        BufferedReader br = null;
        try {

            URL url = new URL(urlPath);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            br = new BufferedReader(new InputStreamReader(con.getInputStream(), STRING_UTF8));
            String input;
            while ((input = br.readLine()) != null) {
                ticket.append(input);
            }
            br.close();
        } catch (RuntimeException | IOException e) {
            Helper.errorLogger(Helper.class, e);
        } finally {
            if (br != null)
                try {
                    br.close();
                } catch (IOException e) {
                    Helper.errorLogger(Helper.class, e);
                }
        }
        return ticket.toString();
    }

    public static <T extends Enum<T>> String getEnumFieldValue(T selectedOption, String fieldName) {
        String fieldVal = "";
        if (selectedOption != null) {
            Field field;
            try {
                field = selectedOption.getClass().getDeclaredField(fieldName);
                field.setAccessible(true);
                fieldVal = (String) field.get(selectedOption);
            } catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
                Helper.errorLogger(Helper.class, e);
            }
        }
        return fieldVal;

    }

    public static double bigDecimal2double(BigDecimal bdVal) {
        double val = 0d;
        if (bdVal != null) {
            val = bdVal.doubleValue();
        }
        return val;

    }

    public static String request2String(Map<String, Object> reqParam, String param) {
        String val = "";
        if (reqParam != null && reqParam.get(param) != null) {
            val = Helper.checkNulls(reqParam.get(param), "");
        }
        return val;
    }

    public static int request2Int(Map<String, Object> reqParam, String param) {
        int val = 0;
        try {
            if (reqParam != null && reqParam.get(param) != null) {
                val = Integer.parseInt((String) reqParam.get(param));
            }
        } catch (NumberFormatException nfe) {
            Helper.errorLogger(Helper.class, nfe, STRING_PARAM + param);
        }
        return val;
    }

    public static double request2Double(Map<String, Object> reqParam, String param) {
        double val = 0;
        try {
            if (reqParam != null && reqParam.get(param) != null) {
                val = Double.parseDouble(String.valueOf(reqParam.get(param)));
            }
        } catch (NumberFormatException nfe) {
            Helper.errorLogger(Helper.class, nfe, STRING_PARAM + param);
        }
        return val;
    }

    public static float request2Float(Map<String, Object> reqParam, String param) {
        float val = 0;
        try {
            if (reqParam != null && reqParam.get(param) != null) {
                val = Float.parseFloat((String) reqParam.get(param));
            }
        } catch (NumberFormatException nfe) {
            Helper.errorLogger(Helper.class, nfe, STRING_PARAM + param);
        }
        return val;
    }

    public static Date request2Date(Map<String, Object> reqParam, String param) {
        return request2Date(reqParam, param, DATE_FORMAT_SHORT);
    }

    public static Date request2Date(Map<String, Object> reqParam, String param, String format) {
        Date val = null;
        try {
            String newFormat = format;
            if (format == null || format.length() < 4) {
                newFormat = DATE_FORMAT_SHORT;
            }
            SimpleDateFormat sdf = new SimpleDateFormat(newFormat);
            if (reqParam != null && reqParam.get(param) != null) {
                String strDate = (String) reqParam.get(param);
                val = sdf.parse(strDate);
            }
        } catch (RuntimeException | ParseException e) {
            Helper.errorLogger(Helper.class, e, STRING_PARAM + param);
        }
        return val;
    }

    public static String repeatString(String str, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(str);
        }
        return sb.toString();
    }

    public static long string2Long(String pval) {
        String val = pval;
        val = Helper.checkNulls(val, "0").trim();
        try {
            return Long.parseLong(val);
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e, "[pval]:" + pval);
        }
        return 0;
    }

    public static boolean checkNumeric(String value) {
        boolean logic = true;
        try {
            Long.parseLong(Helper.checkNulls(value.trim(), ""));
        } catch (NumberFormatException e) {
            logic = false;
        }
        return logic;
    }

    public static java.sql.Timestamp date2Timestamp(Date pdate) {
        Date date = pdate;
        if (date == null) {
            date = new Date();
        }

        return new java.sql.Timestamp(date.getTime());
    }

    public static void log2File(String fileName, String content) {
        log2File(fileName, content, true);
    }

    public static void log2File(String fileName, String content, boolean isTrim) {
        log2File(fileName, content, false, isTrim);
    }

    public static void log2File(String fileName, String pcontent, boolean isAppend, boolean isTrim) {
        String content = pcontent;
        FileWriter fw = null;
        try {
            fw = new FileWriter(new File("/tmp/logfiles/" + fileName), isAppend);
            if (isTrim) {
                content = content.trim();
            }
            fw.write(content);
            fw.close();
        } catch (RuntimeException | IOException e) {
            Helper.errorLogger(Helper.class, e);
        } finally {
            if (fw != null) {
                try {
                    fw.close();
                } catch (IOException e) {
                    Helper.errorLogger(Helper.class, e);
                }
            }
        }
    }

    public static Clob string2Clob(Connection conn, String data) {
        Clob clob = null;
        try {
            clob = conn.createClob();
            clob.setString((long) 1, data);
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return clob;
    }

    public static String validationStringLen(String pstr, int len) {
        String str = pstr;
        str = Helper.checkNulls(str, "");
        if (str.length() > len) {
            return str.substring(0, len);
        } else {
            return str;
        }
    }

    public static String appendStringtoString(String value, String appendedValue, int count) {
        StringBuilder sb = new StringBuilder();
        sb.append(value);
        for (int i = 0; i < count; i++) {
            sb.append(appendedValue);
        }
        return sb.toString();
    }

    public static double string2Double(String val) {
        try {
            NumberFormat nfIn = NumberFormat.getNumberInstance(Locale.GERMANY);
            return nfIn.parse(val).doubleValue();
        } catch (ParseException e) {
            return 0;
        }
    }

    public static int hex2decimal(String ps) {
        String s = ps;
        String digits = "0123456789ABCDEF";
        s = s.toUpperCase(Locale.ENGLISH);
        int val = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = digits.indexOf(c);
            val = 16 * val + d;
        }
        return val;
    }

    // precondition: d is a nonnegative integer
    public static String decimal2hex(int pd) {
        int d = pd;
        String digits = "0123456789ABCDEF";
        if (d == 0) {
            return "0";
        }
        String hex = "";
        while (d > 0) {
            int digit = d % 16; // rightmost digit
            hex = digits.charAt(digit) + hex; // string concatenation
            d = d / 16;
        }
        return hex;
    }

    public static Date dateAddMinute(Date date, int minute) {
        Date newdate = date;
        try {
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            cal.add(Calendar.MINUTE, minute);
            newdate = cal.getTime();

        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return newdate;
    }

    public static String maskCreditCardNo(String cardNo) {
        String mask = Helper.checkNulls(cardNo, "");
        if (cardNo.length() > 14) {
            mask = cardNo.substring(0, 4) + "-" + cardNo.substring(4, 6) + "XX-" + "XXXX-"
                    + cardNo.substring(cardNo.length() - 4, cardNo.length());
        }
        return mask;
    }

    public static int getWeekOfYear(Date date) {
        int thisWeek = -1;
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(date);
            thisWeek = calendar.get(Calendar.WEEK_OF_YEAR);
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return thisWeek;
    }

    public static int getMonthOfDate(Date date) {
        int thisWeek = -1;
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(date);
            thisWeek = calendar.get(Calendar.MONTH) + 1;
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return thisWeek;
    }

    public static int getYearOfDate(Date date) {
        int thisWeek = -1;
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(date);
            thisWeek = calendar.get(Calendar.YEAR);
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return thisWeek;
    }

    public static String double2String(double dbl) {

        DecimalFormatSymbols symbols = new DecimalFormatSymbols(new Locale("en", "US"));
        symbols.setDecimalSeparator('.');
        String pattern = "##0";
        DecimalFormat df = new DecimalFormat(pattern, symbols);
        String number = df.format(dbl);
        return number;
    }

    public static String getLinkShortly(String url) {
        return url;
    }

    public static int getRandomCode() {
        return ThreadLocalRandom.current().nextInt(100000, 999999);
    }

    public static boolean checkValidCoordinate(String coordinate) {
        boolean isValid = false;
        try {
            if (coordinate != null) {
                String regexCoords = "([+-]?\\d+\\.?\\d+)\\s*";
                Pattern compiledPattern2 = Pattern.compile(regexCoords, Pattern.CASE_INSENSITIVE);
                Matcher matcher2 = compiledPattern2.matcher(coordinate);
                while (matcher2.find()) {
                    isValid = true;
                }
            }

        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }

        return isValid;
    }

    public static String generateSha256Hash(String data) {
        String newHash = "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] byteData = digest.digest(data.getBytes(STRING_UTF8));

            newHash = DatatypeConverter.printHexBinary(byteData);

        } catch ( NoSuchAlgorithmException | UnsupportedEncodingException e) {
            Helper.errorLogger(Helper.class, e);
        }

        return newHash;
    }

    public static String date2DB2Timestamp(Date pDate, int addSecond) {
        StringBuilder result = new StringBuilder();
        Date date = pDate;
        if (date == null) {
            date = new Date();
        }
        try {
            result.append(
                    "( TO_DATE('" + Helper.date2String(date, "dd/MM/yyyy HH:mm:ss") + "','DD/MM/YYYY HH24:MI:SS') ");
            if (addSecond > 0) {
                result.append(" + " + addSecond + " SECOND ");
            }
            result.append(")");
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return result.toString();
    }


    public static int getRowCount(ResultSet resultSet) {
        if (resultSet == null) {
            return 0;
        }
        try {
            resultSet.last();
            return resultSet.getRow();
        } catch (SQLException exp) {
            Helper.errorLogger(Helper.class, exp);
        } finally {
            try {
                resultSet.beforeFirst();
            } catch (SQLException exp) {
                Helper.errorLogger(Helper.class, exp);
            }
        }
        return 0;
    }

    public static boolean isIntByRegex(String str) {
        return str.matches("^-?\\d+$");
    }

    public static String clobToString(Clob data) {
        final StringBuilder sb = new StringBuilder();
        try {
            if (data != null) {
                final Reader reader = data.getCharacterStream();
                final BufferedReader br = new BufferedReader(reader);

                int b;
                while (-1 != (b = br.read())) {
                    sb.append((char) b);
                }
                br.close();
            }
        } catch (SQLException | IOException e) {
            Helper.errorLogger(Helper.class, e);
        }
        return sb.toString();
    }

    public static Date getToday() {
        return Helper.string2Date(Helper.date2String(new Date()));
    }

    public static Date setHour2Date(Date date, int hour) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.set(Calendar.HOUR_OF_DAY, hour);
        return calendar.getTime();
    }

    public static Date setMinute2Date(Date date, int minute) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.set(Calendar.MINUTE, minute);
        return calendar.getTime();
    }

    public static String castDB2OrderBy(String... fields) {
        StringBuilder orderBy = new StringBuilder();
        int fieldCount = fields.length;
        int indx = 0;
        for (String field : fields) {
            orderBy.append(" COLLATION_KEY_BIT (" + field + ", 'UCA500R1_LTR_AN_CX_EX_FX_HX_NX_S3') ");
            indx++;
            if (indx < fieldCount) {
                orderBy.append(",");
            }
        }
        return orderBy.toString();
    }

    public static String generateKeyForData(String data,String APP_ACTIVE_PROFILE) {
        try {
            JWTUtil jwt = JWTUtil.create().setEnvironment(APP_ACTIVE_PROFILE).setExpireTime(28800).build();
            Map<String, String> claims = new HashMap<>();
            claims.put("data", data);
            return jwt.generateTokenWithJWT(claims);
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }

        return "";
    }


    public static String imageToBase64String(File imageFile) {

        String image = null;
        try {
            String fileType = java.nio.file.Files.probeContentType(imageFile.toPath());
            if (fileType != null && !fileType.startsWith("image")) {
               // throw new HBRuntimeException("Hatalı dosya tipi!");
            }
            if (fileType == null)
                return image;

            BufferedImage buffImage = ImageIO.read(imageFile);

            if (buffImage != null) {
                java.io.ByteArrayOutputStream os = new java.io.ByteArrayOutputStream();
                ImageIO.write(buffImage, "jpg", os);
                byte[] data = os.toByteArray();
                // image = HBBase64.encode(data);
            }
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
        return image;
    }


    /**
     * DB'de ki smallint type kolonunun java karşılığını döner.
     *
     * @param value : 0 ya da 1
     * @return : true ya da false
     */
    public static boolean convertSmallIntToBoolean(int value) {
        if (value == 1) {
            return true;
        }
        return false;
    }

    /**
     * Java da ki boolean field'ın DB de ki SMALLINT karşılığını döner.
     *
     * @param value : true ya da false
     * @return : 0 ya da 1
     */
    public static int convertBooleanToSmallInt(boolean value) {
        if (value) {
            return 1;
        }
        return 0;
    }

    public static String convert2Json(Object obj) {
        return ToStringBuilder.reflectionToString(obj, ToStringStyle.JSON_STYLE);
    }

    /**
     * Girilen tarih parametresi ile bugünkü tarih arasında ki geçen süreyi
     * hesaplayıp; <br>
     * x gün önce,x dakika önce ya da x saat önce döner
     *
     * @param olusturmaTarihi : Geçmişte ki bir tarih (Timestamp biçiminde gönderilir)
     * @return
     */
    public static String gecenSureHesapla(Date olusturmaTarihi) {
        String yayinlanmaSure = "";
        int sure = (int) Helper.dateDifferent(olusturmaTarihi, new Date(), Calendar.DATE);
        if (sure > 0) {
            if (sure >= 30 && sure < 365) {
                yayinlanmaSure = (sure / 30) + " ay önce";
            } else if (sure < 30) {
                yayinlanmaSure = sure + " gün önce";
            } else if (sure >= 30 && sure >= 365) {
                yayinlanmaSure = (sure / 365) + " yıl önce";
            }
        } else {
            sure = (int) Helper.dateDifferent(olusturmaTarihi, new Date(), Calendar.HOUR);
            if (sure == 0) {
                sure = (int) Helper.dateDifferent(olusturmaTarihi, new Date(), Calendar.MINUTE);
                yayinlanmaSure = sure + " dakika önce";
            } else {
                yayinlanmaSure = sure + " saat önce";
            }
        }
        return yayinlanmaSure;
    }

    public static String calcElapedTimeAsString(Date beginDate, Date endDate) {

        long different = endDate.getTime() - beginDate.getTime();

        long secondsInMilli = 1000;
        long minutesInMilli = secondsInMilli * 60;
        long hoursInMilli = minutesInMilli * 60;
        long daysInMilli = hoursInMilli * 24;

        long elapsedDays = different / daysInMilli;
        different = different % daysInMilli;

        long elapsedHours = different / hoursInMilli;
        different = different % hoursInMilli;

        long elapsedMinutes = different / minutesInMilli;
        different = different % minutesInMilli;

        long elapsedSeconds = different / secondsInMilli;

        return String.format("%d gün, %d saat, %d dakika, %d saniye", elapsedDays, elapsedHours, elapsedMinutes,
                elapsedSeconds);
    }


    public static boolean checkAndCreateDirectory(String path, boolean createDir) {
        File dir = null;
        try {
            dir = new File(path);
            if (dir.exists()) {
                return true;
            } else if (createDir) {
                return dir.mkdirs();
            }
        } catch (RuntimeException e) {
            Helper.errorLogger(Helper.class, e);
        } finally {
            dir = null;
        }
        return false;
    }

    public static void deleteFolderFiles(String folderPath, int min) {
        try {
            File dir = new File(folderPath);
            if (dir.exists()) {
                BasicFileAttributes attr;
                Date now = new Date();
                for (File file : dir.listFiles()) {
                    attr = java.nio.file.Files.readAttributes(file.toPath(), BasicFileAttributes.class);
                    if (Helper.dateDifferent(new Date(attr.creationTime().toMillis()), now, Calendar.MINUTE) > min) {
                        file.delete();
                    }
                }
            }
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
        }
    }

    public static String convertMailStrTR(String str) {

        int unicodeIntValue = 0;
        String unicodeString = "";
        String ucValue = "";
        if (str == null)
            return null;
        try {
            int length = str.length();
            for (int i = 0; i < length; i++) {
                unicodeIntValue = str.charAt(i);
                if (unicodeIntValue == 38) {// & ile basliyorsa
                    ucValue = "" + str.charAt(i) + str.charAt(i + 1) + str.charAt(i + 2) + str.charAt(i + 3)
                            + str.charAt(i + 4);
                    if (ucValue != null && ucValue.equals("&#304")) {
                        unicodeString += "&#304;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#305")) {
                        unicodeString += "&#305;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#214")) {
                        unicodeString += "&Ouml;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#246")) {
                        unicodeString += "&ouml;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#220")) {
                        unicodeString += "&Uuml;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#252")) {
                        unicodeString += "&uuml;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#199")) {
                        unicodeString += "&Ccedil;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#231")) {
                        unicodeString += "&ccedil;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#286")) {
                        unicodeString += "&#286;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#287")) {
                        unicodeString += "&#287;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#350")) {
                        unicodeString += "&#350;";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#351")) {
                        unicodeString += "&#351;";
                        i = i + 5;
                        continue;
                    }
                }
                if (unicodeIntValue == 221 || unicodeIntValue == 304) {
                    unicodeString += "&#304;";
                    continue;
                }
                if (unicodeIntValue == 253 || unicodeIntValue == 305) {
                    unicodeString += "&#305;";
                    continue;
                }
                if (unicodeIntValue == 254 || unicodeIntValue == 351) {
                    unicodeString += "&#351;";
                    continue;
                }
                if (unicodeIntValue == 222 || unicodeIntValue == 350) {
                    unicodeString += "&#350;";
                    continue;
                }
                if (unicodeIntValue == 208 || unicodeIntValue == 286) {
                    unicodeString += "&#286;";
                    continue;
                }
                if (unicodeIntValue == 240 || unicodeIntValue == 287) {
                    unicodeString += "&#287;";
                    continue;
                }
                if (unicodeIntValue == 231) {
                    unicodeString += "&ccedil;";
                    continue;
                }
                if (unicodeIntValue == 199) {
                    unicodeString += "&Ccedil;";
                    continue;
                }
                if (unicodeIntValue == 252) {
                    unicodeString += "&uuml;";
                    continue;
                }
                if (unicodeIntValue == 220) {
                    unicodeString += "&Uuml;";
                    continue;
                }
                if (unicodeIntValue == 246) {
                    unicodeString += "&ouml;";
                    continue;
                }
                if (unicodeIntValue == 214) {
                    unicodeString += "&Ouml;";
                    continue;
                }
                unicodeString += (char) unicodeIntValue;
            }
            return unicodeString;
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
            return "no content";
        }
    }

    public static Date dateFormatConvert(String strDate, String format) {
        Date date = null;
        try {
            if (strDate.indexOf(".0Z") > -1) {
                strDate = strDate.replace("T", " ");
                strDate = strDate.replace(".0Z", "");
            }
            date = (new SimpleDateFormat(format, Locale.FRENCH)).parse(strDate);
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e, "[strDate]:" + strDate + " [format]:" + format);
        }
        return date;
    }




    public static String utfConvStrEng(String str) {
        int unicodeIntValue = 0;
        String unicodeString = "";
        String ucValue = "";
        if (str == null)
            return null;
        try {
            int length = str.length();

            for (int i = 0; i < length; i++) {
                unicodeIntValue = str.charAt(i);

                // System.out.println(((char) unicodeIntValue) + " = " + unicodeIntValue);

                if (unicodeIntValue == 38) {// & ile basliyorsa
                    ucValue = "" + str.charAt(i) + str.charAt(i + 1) + str.charAt(i + 2) + str.charAt(i + 3)
                            + str.charAt(i + 4);
                    if (ucValue != null && ucValue.equals("&#304")) {
                        unicodeString += "I";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#305")) {
                        unicodeString += "i";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#214")) {
                        unicodeString += "O";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#246")) {
                        unicodeString += "o";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#220")) {
                        unicodeString += "U";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#252")) {
                        unicodeString += "u";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#199")) {
                        unicodeString += "C";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#231")) {
                        unicodeString += "c";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#286")) {
                        unicodeString += "G";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#287")) {
                        unicodeString += "g";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#350")) {
                        unicodeString += "S";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("&#351")) {
                        unicodeString += "s";
                        i = i + 5;
                        continue;
                    }

                }

                if (unicodeIntValue == 37) {
                    ucValue = "" + str.charAt(i) + str.charAt(i + 1) + str.charAt(i + 2) + str.charAt(i + 3)
                            + str.charAt(i + 4) + str.charAt(i + 5);
                    if (ucValue != null && ucValue.equals("%C4%B1")) {
                        unicodeString += "I";
                        i = i + 5;
                        continue;
                    }

                    if (ucValue != null && ucValue.equals("%C4%9F")) {
                        unicodeString += "G";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("%C3%BC")) {
                        unicodeString += "Ş";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("%C4%B0")) {
                        unicodeString += "İ";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("%C3%B6")) {
                        unicodeString += "Ö";
                        i = i + 5;
                        continue;
                    }
                    if (ucValue != null && ucValue.equals("%C3%A7")) {
                        unicodeString += "Ç";
                        i = i + 5;
                        continue;
                    }
                }

                if (unicodeIntValue == 221 || unicodeIntValue == 304) {
                    unicodeString += "I";
                    continue;
                }
                if (unicodeIntValue == 253 || unicodeIntValue == 305) {
                    unicodeString += "i";
                    continue;
                }
                if (unicodeIntValue == 254 || unicodeIntValue == 351) {
                    unicodeString += "s";
                    continue;
                }
                if (unicodeIntValue == 222 || unicodeIntValue == 350) {
                    unicodeString += "S";
                    continue;
                }
                if (unicodeIntValue == 208 || unicodeIntValue == 286) {
                    unicodeString += "G";
                    continue;
                }
                if (unicodeIntValue == 240 || unicodeIntValue == 287) {
                    unicodeString += "g";
                    continue;
                }
                if (unicodeIntValue == 231) {
                    unicodeString += "c";
                    continue;
                }
                if (unicodeIntValue == 199) {
                    unicodeString += "C";
                    continue;
                }
                if (unicodeIntValue == 252) {
                    unicodeString += "u";
                    continue;
                }
                if (unicodeIntValue == 220) {
                    unicodeString += "U";
                    continue;
                }
                if (unicodeIntValue == 246) {
                    unicodeString += "o";
                    continue;
                }
                if (unicodeIntValue == 214) {
                    unicodeString += "O";
                    continue;
                }

                unicodeString += (char) unicodeIntValue;
            }
            return unicodeString;
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
            return "";
        }
    }

    public static String utfConvStrForHtml(String str) {
        int unicodeIntValue = 0;
        String unicodeString = "";
        if (str == null)
            return null;
        try {
            int length = str.length();

            for (int i = 0; i < length; i++) {
                unicodeIntValue = str.charAt(i);

                // System.out.println(unicodeIntValue +" : "+ (char) unicodeIntValue);
                /*
                 * 305 : ı 287 : ğ 252 : ü 351 : ş 105 : i 246 : ö 231 : ç 286 : Ğ 220 : Ü 350 :
                 * Ş 304 : İ 214 : Ö 199 : Ç
                 */

                if (unicodeIntValue == 305) {
                    unicodeString += "&#305;";
                    continue;
                }
                if (unicodeIntValue == 287) {
                    unicodeString += "&#287;";
                    continue;
                }
                if (unicodeIntValue == 252) {
                    unicodeString += "&#252;";
                    continue;
                }
                if (unicodeIntValue == 351) {
                    unicodeString += "&#351;";
                    continue;
                }

                if (unicodeIntValue == 246) {
                    unicodeString += "&#246;";
                    continue;
                }

                if (unicodeIntValue == 231) {
                    unicodeString += "&#231;";
                    continue;
                }
                if (unicodeIntValue == 286) {
                    unicodeString += "&#286;";
                    continue;
                }
                if (unicodeIntValue == 220) {
                    unicodeString += "&#220;";
                    continue;
                }
                if (unicodeIntValue == 350) {
                    unicodeString += "&#350;";
                    continue;
                }
                if (unicodeIntValue == 304) {
                    unicodeString += "&#304;";
                    continue;
                }
                if (unicodeIntValue == 214) {
                    unicodeString += "&#214;";
                    continue;
                }
                if (unicodeIntValue == 199) {
                    unicodeString += "&#199;";
                    continue;
                }
                if (unicodeIntValue == 63) {
                    unicodeString += "&#63;";
                }
                unicodeString += (char) unicodeIntValue;
            }
            return unicodeString;
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);
            return "";
        }
    }

    public static boolean checkFolderExist(String folderPath) {
        boolean exists = false;
        File folder = new File(folderPath);
        if (!folder.exists()) {
            folder.mkdirs();
        }
        return exists;
    }

    public static List checkEmptyForList(List list) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }
        return list;
    }

    public static String checkNullStringDB(String s) {
        if (s == null) {
            return "null";
        } else {
            return "'" + s + "'";
        }

    }

    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Applies sha256 to our input,
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer(); // This will contain hash as hexidecimal
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }



    public static String utfConvStr(String str) {
        int unicodeIntValue = 0;
        String unicodeString = "";
        if (str == null)
            return null;
        try {
            int length = str.length();

            for (int i = 0; i < length; i++) {
                unicodeIntValue = str.charAt(i);
                // System.out.println("unicodeIntValue:"+unicodeIntValue);
                if (unicodeIntValue == 220) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 252) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 214) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 246) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 199) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 231) {
                    unicodeString += "�";
                    continue;
                }

                if (unicodeIntValue == 221) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 253) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 254) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 222) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 208) {
                    unicodeString += "�";
                    continue;
                }
                if (unicodeIntValue == 240) {
                    unicodeString += "�";
                    continue;
                }
                unicodeString += (char) unicodeIntValue;
            }
            return unicodeString;
        } catch (Exception e) {
            System.out.println("unicodeConvert problem: " + e.getMessage());
            return " ";
        }
    }







    public static String findDomesticFlight(String airline, String from, String to, Connection conn) {
        String strID = "IC";
        StringBuffer sql = new StringBuffer();
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            if (airline != null && airline.length() > 2 && from != null && from.length() > 2 && to != null && to.length() > 2) {

                sql.append("SELECT ");
                sql.append("    NVL(A.INTDOM,'I') INTDOM ");
                sql.append("FROM ads.ads_citypair a ");
                sql.append("WHERE ");
                sql.append("	A.AIRLINE = ? ");
                sql.append("	AND A.FROM_CODE=? ");
                sql.append("	AND A.TO_CODE =? ");


                st = conn.prepareStatement(sql.toString());
                st.setString(1, airline);
                st.setString(2, from);
                st.setString(3, to);
                rs = st.executeQuery();
                while (rs.next()) {
                    strID = rs.getString("INTDOM");
                }
                rs.close();
                st.close();
            }
        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e, "[SQL]:" + sql.toString() + " [airline]: " + airline + " [from]: " + from + " [to]: " + to);
        } finally {
            sql = null;

        }

        return strID;
    }



    public static String decrypt(String encrypted) {

        byte[] decryptedBytes = null;
        try {
            ivParameterSpec = new IvParameterSpec(SECRET_KEY_1.getBytes("UTF-8"));
            secretKeySpec = new SecretKeySpec(SECRET_KEY_2.getBytes("UTF-8"), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            decryptedBytes = cipher.doFinal(Base64.decodeBase64(encrypted.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return new String(decryptedBytes);
    }

    public static String checkTcketNumber(String ticketNum) {
        String retval = "NOK";
        try {
            if (ticketNum != null && ticketNum.indexOf(".") > -1) {
                retval = ticketNum.substring(0, ticketNum.indexOf("."));
            }

        } catch (Exception e) {
            errorLogger(Helper.class, e);

        }
        return retval;
    }
    public static int getFlightLeg(String ticketNum) {
        int retval = 1;
        try {
            if (ticketNum != null && ticketNum.indexOf(".") > -1) {
                //Helper.log("Ticket Num: " + ticketNum.substring(ticketNum.indexOf(".") + 1, ticketNum.length()));
                retval = Integer.parseInt(ticketNum.substring(ticketNum.indexOf(".") + 1, ticketNum.length()));
            }

        } catch (Exception e) {
            Helper.errorLogger(Helper.class, e);

        }
        return retval;
    }
}
