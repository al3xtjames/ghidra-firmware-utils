package firmware.fmap;

/**
 * Various Flash Map (FMAP) constants.
 */
public final class FlashMapConstants {
	// Flash Map signature
	public static final String FMAP_SIGNATURE = "__FMAP__";

	// Flash Map name length (including null terminator)
	public static final int FMAP_NAME_LEN = 32;

	// Flash Map area flags
	public static final byte FMAP_AREA_STATIC = 1 << 0;
	public static final byte FMAP_AREA_COMPRESSED = 1 << 1;
	public static final byte FMAP_AREA_READONLY = 1 << 2;
	public static final byte FMAP_AREA_PRESERVE = 1 << 3;
}
