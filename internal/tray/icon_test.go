package tray

import "testing"

func TestIconICO(t *testing.T) {
	img, err := iconImage(iconICO)
	if err != nil {
		t.Fatal(err)
	}
	if len(img) < 40 {
		t.Fatalf("короткий образ %d", len(img))
	}
	if img[0] != 40 || img[1] != 0 || img[2] != 0 || img[3] != 0 {
		t.Fatal("нет BITMAPINFOHEADER")
	}
}
