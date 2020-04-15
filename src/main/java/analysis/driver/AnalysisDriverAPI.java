package analysis.driver;

import analysis.AnalysisSettings;
import analysis.AnalysisSettings.EpsilonLoopRemovalStrategy;
import analysis.AnalysisSettings.NFAConstruction;
import analysis.AnalysisSettings.PreprocessingType;
import analysis.AnalysisSettings.PriorityRemovalStrategy;
import analysis.NFAAnalyser;
import analysis.NFAAnalyserFlattening;
import analysis.NFAAnalyserInterface;
import analysis.NFAAnalyserInterface.AnalysisResultsType;
import analysis.NFAAnalyserMerging;
import analysis.exception.AnalysisException;
import nfa.NFAGraph;
import preprocessor.NonpreciseSubstitutionPreprocessor;
import preprocessor.PreciseSubstitutionPreprocessor;
import preprocessor.Preprocessor;
import regexcompiler.MyPattern;
import util.Constants;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AnalysisDriverAPI {

  private final NFAConstruction nfaConstruction;
  private final PreprocessingType preprocessingType;
  private final EpsilonLoopRemovalStrategy epsilonLoopRemovalStrategy;
  private final PriorityRemovalStrategy priorityRemovalStrategy;
  private final boolean shouldTestIDA;
  private final int timeout;
  private final boolean timeoutEnabled;

  private AnalysisDriverAPI(NFAConstruction nfaConstruction,
      PreprocessingType preprocessingType,
      EpsilonLoopRemovalStrategy epsilonLoopRemovalStrategy,
      PriorityRemovalStrategy priorityRemovalStrategy, boolean shouldTestIDA, int timeout) {
    this.nfaConstruction = nfaConstruction;
    this.preprocessingType = preprocessingType;
    this.epsilonLoopRemovalStrategy = epsilonLoopRemovalStrategy;
    this.priorityRemovalStrategy = priorityRemovalStrategy;
    this.shouldTestIDA = shouldTestIDA;
    this.timeout = timeout;
    if (timeout > 0) {
      timeoutEnabled = true;
    } else {
      timeoutEnabled = false;
    }
  }

  /**
   *  Check if a regex is vulnerable
   *
   * @param pattern regex to analyse
   * @return true if the pattern is vulnerable
   */
  public boolean isVulnerable(String pattern) throws AnalysisException {
    NFAAnalyserInterface analyser = getCorrectNFAAnalyser(epsilonLoopRemovalStrategy);

    Pattern slashesRegex = Pattern.compile("^/(.*)/[a-zA-Z]*$");
    try {
			/* To allow for the convention of writing regular expressions as / ... /, we simply take
			that in ... */
      Matcher slashMatcher = slashesRegex.matcher(pattern);
      if (slashMatcher.find()) {
        pattern = slashMatcher.group(1);
      }
      String finalPattern = preprocessToFinalPattern(pattern);

      AnalysisRunner ar = new AnalysisRunner(finalPattern, analyser);

      final Thread AnalysisRunnerThread = new Thread(ar);
      Thread sleepThread = new Thread() {
        public void run() {
          try {
            if (timeoutEnabled) {
              Thread.sleep(timeout * Constants.MILLISECONDS_IN_SECOND);
              AnalysisRunnerThread.interrupt();
            }
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
        }
      };

      AnalysisRunnerThread.start();
      sleepThread.start();
      AnalysisRunnerThread.join();
      sleepThread.interrupt();

      if(ar.getThrowable().isPresent()){
        throw new AnalysisException(ar.getThrowable().get());
      }

      AnalysisResultsType results = ar.getAnalysisResultsType();
      switch (results) {
        case EDA:
        case IDA:
          return true;
        case NO_EDA:
        case NO_IDA:
          return false;
        case TIMEOUT_IN_EDA:
          throw new AnalysisException("Timeout during EDA testing");
        case TIMEOUT_IN_IDA:
          throw new AnalysisException("Timeout during IDA testing");
        case ANALYSIS_FAILED:
          throw new AnalysisException("Analysis failed");
      }
    } catch (Exception e) {
    	throw new AnalysisException(e.getMessage(), e);
    }
    return true;
  }

  private NFAAnalyser getCorrectNFAAnalyser(
      EpsilonLoopRemovalStrategy epsilonLoopRemovalStrategy) {
    NFAAnalyser analyser;
    switch (epsilonLoopRemovalStrategy) {
      case MERGING:
        analyser = new NFAAnalyserMerging(priorityRemovalStrategy);
        break;
      case FLATTENING:
        analyser = new NFAAnalyserFlattening(priorityRemovalStrategy);
        break;
      default:
        throw new RuntimeException("Unknown Strategy: " + epsilonLoopRemovalStrategy);
    }
    return analyser;
  }

  private String preprocessToFinalPattern(String pattern) throws AnalysisException {
    Preprocessor preprocessor;
    String finalPattern;
    switch (preprocessingType) {
      case NONE:
        finalPattern = pattern;
        break;
      case PRECISE:
        preprocessor = new PreciseSubstitutionPreprocessor();
        finalPattern = preprocessor.applyRules(pattern);
        break;
      case NONPRECISE:
        preprocessor = new NonpreciseSubstitutionPreprocessor();
        finalPattern = preprocessor.applyRules(pattern);
        break;
      default:
        throw new AnalysisException("Unknown preprocessing type: " + preprocessingType);
    }
    return finalPattern;
  }

  public static AnalysisDriverAPIBuilder builder(){
    return new AnalysisDriverAPIBuilder();
  }

  public static class AnalysisDriverAPIBuilder {
    private AnalysisSettings.NFAConstruction nfaConstruction = AnalysisSettings.NFAConstruction.JAVA;
    private AnalysisSettings.PreprocessingType preprocessingType = AnalysisSettings.PreprocessingType.NONE;
    private AnalysisSettings.EpsilonLoopRemovalStrategy epsilonLoopRemovalStrategy =
        AnalysisSettings.EpsilonLoopRemovalStrategy.FLATTENING;
    private AnalysisSettings.PriorityRemovalStrategy priorityRemovalStrategy =
        AnalysisSettings.PriorityRemovalStrategy.UNPRIORITISE;
    private boolean shouldTestIDA = true;
    private int timeout = 10;

    public AnalysisDriverAPIBuilder setNfaConstruction(
        AnalysisSettings.NFAConstruction nfaConstruction) {
      this.nfaConstruction = nfaConstruction;
      return this;
    }

    public AnalysisDriverAPIBuilder setPreprocessingType(
        AnalysisSettings.PreprocessingType preprocessingType) {
      this.preprocessingType = preprocessingType;
      return this;
    }

    public AnalysisDriverAPIBuilder setEpsilonLoopRemovalStrategy(
        AnalysisSettings.EpsilonLoopRemovalStrategy epsilonLoopRemovalStrategy) {
      this.epsilonLoopRemovalStrategy = epsilonLoopRemovalStrategy;
      return this;
    }

    public AnalysisDriverAPIBuilder setPriorityRemovalStrategy(
        AnalysisSettings.PriorityRemovalStrategy priorityRemovalStrategy) {
      this.priorityRemovalStrategy = priorityRemovalStrategy;
      return this;
    }

    public AnalysisDriverAPIBuilder setShouldTestIDA(boolean shouldTestIDA) {
      this.shouldTestIDA = shouldTestIDA;
      return this;
    }

    public AnalysisDriverAPIBuilder setTimeout(int timeout) {
      this.timeout = timeout;
      return this;
    }

    public AnalysisDriverAPI build() {
      return new AnalysisDriverAPI(nfaConstruction, preprocessingType, epsilonLoopRemovalStrategy,
          priorityRemovalStrategy, shouldTestIDA, timeout);
    }
  }

  private class AnalysisRunner implements Runnable {
    private final String pattern;
    private final NFAAnalyserInterface analyser;
    private AnalysisResultsType analysisResultsType;
    private Optional<Throwable> throwable;

    private AnalysisRunner(String pattern, NFAAnalyserInterface analyser) {
      this.pattern = pattern;
      this.analyser = analyser;
    }

    public AnalysisResultsType getAnalysisResultsType() {
      return analysisResultsType;
    }

    public Optional<Throwable> getThrowable() {
      return throwable;
    }

    @Override
    public void run() {
      try {
        NFAGraph analysisGraph = MyPattern.toNFAGraph(pattern, nfaConstruction);
        analysisResultsType = analyser.containsEDA(analysisGraph);
        switch (analysisResultsType){
          case EDA:
          case TIMEOUT_IN_EDA:
          case ANALYSIS_FAILED:
            break;
          case NO_EDA:
            if (shouldTestIDA) {
              analysisResultsType = analyser.containsIDA(analysisGraph);
            }
        }
        throwable = Optional.empty();
      } catch (Exception | OutOfMemoryError e) {
        analysisResultsType = AnalysisResultsType.ANALYSIS_FAILED;
        throwable = Optional.of(e);
        Thread.currentThread().interrupt();
      }
    }
  }
}


