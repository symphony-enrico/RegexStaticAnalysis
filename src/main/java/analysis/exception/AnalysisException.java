package analysis.exception;

/**
 * @author enrico.molino (21/04/2020)
 */
public class AnalysisException extends Exception {

  public AnalysisException(String message) {
    super(message);
  }

  public AnalysisException(String message, Throwable cause) {
    super(message, cause);
  }

  public AnalysisException(Throwable cause) {
    super(cause.getMessage(), cause);

  }
}
