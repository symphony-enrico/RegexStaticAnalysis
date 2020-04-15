package driver;

import analysis.driver.AnalysisDriverAPI;
import analysis.exception.AnalysisException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.saferegex.RegexTester;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author enrico.molino (15/04/2020)
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AnalysisDriverAPITest {

  private AnalysisDriverAPI api = AnalysisDriverAPI.builder().setTimeout(60).build();

  private static final String REGEX_1 = "ab*(\\.ab*)*";
  private static final String REGEX_2 = "^(a+)+$";
  private static final String REGEX_3 = "(a+)+";
  private static final String REGEX_4 = "([a-zA-Z]+)*";
  private static final String REGEX_5 = "^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@)"
      + "{1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$";
  private static final String REGEX_6 = "^(([a-z])+.)+[A-Z]([a-z])+$";

  @Order(1)
  @Test
  @DisplayName("RegexStaticAnalysis: " + REGEX_1)
  void testRegex1_RegexStaticAnalysis() throws AnalysisException {
    Assertions.assertFalse(api.isVulnerable(REGEX_1));
  }

  @Order(2)
  @Test
  @DisplayName("RegexTester: " + REGEX_1)
  void testRegex1_RegexTester(){
    Assertions.assertFalse(RegexTester.isVulnerable(REGEX_1));
  }

  @Order(3)
  @Test
  @DisplayName("RegexStaticAnalysis: " + REGEX_2)
  void testRegex2_RegexStaticAnalysis() throws AnalysisException {
    Assertions.assertTrue(api.isVulnerable(REGEX_2));
  }

  @Order(4)
  @Test
  @DisplayName("RegexTester: " + REGEX_2)
  void testRegex2_RegexTester(){
    Assertions.assertTrue(RegexTester.isVulnerable(REGEX_2));
  }

  @Order(5)
  @Test
  @DisplayName("RegexStaticAnalysis: " + REGEX_3)
  void testRegex3_RegexStaticAnalysis() throws AnalysisException {
    Assertions.assertTrue(api.isVulnerable(REGEX_3));
  }

  @Order(6)
  @Test
  @DisplayName("RegexTester: " + REGEX_3)
  void testRegex3_RegexTester(){
    Assertions.assertTrue(RegexTester.isVulnerable(REGEX_3));
  }

  @Order(7)
  @Test
  @DisplayName("RegexStaticAnalysis: " + REGEX_4)
  void testRegex4_RegexStaticAnalysis() throws AnalysisException {
    Assertions.assertTrue(api.isVulnerable(REGEX_4));
  }

  @Order(8)
  @Test
  @DisplayName("RegexTester: " + REGEX_4)
  void testRegex4_RegexTester(){
    Assertions.assertTrue(RegexTester.isVulnerable(REGEX_4));
  }

  @Order(9)
  @Test
  @DisplayName("RegexStaticAnalysis: " + REGEX_5)
  void testRegex5_RegexStaticAnalysis() throws AnalysisException {
    Assertions.assertTrue(api.isVulnerable(REGEX_5));
  }

  @Order(10)
  @Test
  @DisplayName("RegexTester: " + REGEX_5)
  void testRegex5_RegexTester(){
    Assertions.assertTrue(RegexTester.isVulnerable(REGEX_5));
  }

  @Order(11)
  @Test
  @DisplayName("RegexStaticAnalysis: " + REGEX_6)
  void testRegex6_RegexStaticAnalysis() throws AnalysisException {
    Assertions.assertTrue(api.isVulnerable(REGEX_6));
  }

  @Order(12)
  @Test
  @DisplayName("RegexTester: " + REGEX_6)
  void testRegex6_RegexTester(){
    Assertions.assertTrue(RegexTester.isVulnerable(REGEX_6));
  }

  @Order(13)
  @Test
  void testFileInput_RegexStaticAnalysis_vs_RegexTester() throws IOException, AnalysisException {
    String filename = "junit-test.txt";

    InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filename);
    Map<String, Boolean> regexStaticAnalysisresults = new HashMap<>();
    Map<String, Boolean> regexTesterresults = new HashMap<>();
    Set<String> exceptions = new HashSet<>();
    String line;
    int regexTesterErrors = 0;

    System.out.println("RegexStaticAnalysis start test");
    long staticAnalysisTime = System.currentTimeMillis();
    try(BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))){
      while ((line = br.readLine()) != null) {
          System.out.println(line);
          regexStaticAnalysisresults.put(line, api.isVulnerable(line));
      }
    }
    staticAnalysisTime = System.currentTimeMillis() - staticAnalysisTime;

    inputStream = getClass().getClassLoader().getResourceAsStream(filename);

    System.out.println("------------------------------");
    System.out.println("RegexTester start test");
    long regexTester = System.currentTimeMillis();
    try(BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))){
      while ((line = br.readLine()) != null) {
        try {
          regexTesterresults.put(line, RegexTester.isVulnerable(line));
        } catch (Throwable e){
          exceptions.add(e.getMessage());
          regexTesterresults.put(line, null);
          regexTesterErrors++;
        }
      }
    }
    regexTester = System.currentTimeMillis() - regexTester;

    System.out.println(String.format("Total line processed with RegexStaticAnalysis: %d (%d ms) - RegexTester: %d (%d ms)", regexStaticAnalysisresults.size(), staticAnalysisTime, regexTesterresults.size(), regexTester));
    int sameResult = 0;
    int differentResult = 0;
    int regexStaticAnalysisMorePositive = 0;
    for(String regex: regexStaticAnalysisresults.keySet()){
      System.out.println(String.format("%s - RegexStaticAnalysis: %s / RegexTester %s", regex, regexStaticAnalysisresults.get(regex), regexTesterresults.get(regex)));
      if(regexStaticAnalysisresults.get(regex).equals(regexTesterresults.get(regex))){
        sameResult++;
      } else {
        differentResult++;
        if(regexStaticAnalysisresults.get(regex)){
          regexStaticAnalysisMorePositive++;
        }
      }
    }
    System.out.println(String.format("Same results: %d - Different results: %d - Static analysis more positive: %d - RegexTester errors: %d", sameResult, differentResult, regexStaticAnalysisMorePositive, regexTesterErrors));
    System.out.println("Errors:");
    for(String error:exceptions){
      System.out.println(error);
    }
  }
}